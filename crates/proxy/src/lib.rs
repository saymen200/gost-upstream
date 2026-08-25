pub mod ca;
pub mod hook;
mod route_cache;

use ca::Ca;
use hook::InterceptHook;
use route_cache::{Route, RouteCache};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Поднимает MITM-прокси на `listen_addr`. Браузер/curl настраивается на
/// него как на HTTP-прокси (`-x http://PORT`). Для HTTPS браузер шлёт
/// CONNECT — дальше термируем TLS сами (с листовым сертификатом от своего
/// CA) и связываем байты с настоящим TLS-соединением до цели. Для обычного
/// http:// браузер шлёт запрос с абсолютным URI прямо в открытую, без
/// CONNECT и TLS вообще — эту ветку тоже нужно уметь, иначе любой
/// http-ресурс (а их на страницах много даже сейчас — favicon, миксед-
/// контент, OCSP и т.п.) рвётся с ошибкой "expected CONNECT".
///
/// Если прямой TLS до цели не удаётся (нет общего cipher suite и т.п. —
/// типичный симптом ГОСТ-only сайта), прокси автоматически ретраит через
/// gost-engine. Два варианта, где он крутится: `Vm` — на отдельной машине
/// по SSH (крипто-плечо изолировано), `Host` — прямо на этой же машине
/// (проще, без VM, но крипто-код исполняется тут же). `None` в `run()` —
/// фолбэка нет вообще, прямой TLS — единственная попытка.
#[derive(Clone)]
pub enum GostFallback {
    Vm { ssh_target: String, openssl_cnf_path: String, timeout: Duration },
    Host { openssl_cnf_path: String, timeout: Duration },
}

/// Каждый запрос перед отправкой проходит через `hook` (см. `hook.rs`) —
/// им сервер может показать трафик и приостановить его для редактирования.
/// `hook::PassThrough` — прежнее полностью прозрачное поведение.
pub fn run(
    listen_addr: &str,
    ca: Arc<Ca>,
    hook: Arc<dyn InterceptHook>,
    gost: Option<GostFallback>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen_addr)?;
    println!("proxy listening on {listen_addr}");
    let routes = Arc::new(RouteCache::new());
    for stream in listener.incoming() {
        let stream = stream?;
        let ca = ca.clone();
        let hook = hook.clone();
        let gost = gost.clone();
        let routes = routes.clone();
        thread::spawn(move || {
            if let Err(e) = handle_connection(stream, &ca, hook.as_ref(), gost.as_ref(), &routes) {
                eprintln!("connection error: {e}");
            }
        });
    }
    Ok(())
}

fn handle_connection(
    mut client: TcpStream,
    ca: &Ca,
    hook: &dyn InterceptHook,
    gost: Option<&GostFallback>,
    routes: &RouteCache,
) -> anyhow::Result<()> {
    let first_line = read_line_raw(&mut client)?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();

    if method == "CONNECT" {
        handle_connect_tunnel(client, &target, ca, hook, gost, routes)
    } else if !method.is_empty() {
        handle_plain_http(client, &method, &target, hook)
    } else {
        Ok(()) // клиент закрылся, ничего не прислав
    }
}

/// HTTPS: CONNECT + TLS termination + свежее TLS-соединение до цели на
/// каждый запрос внутри туннеля (см. комментарий у read_one_http_message).
fn handle_connect_tunnel(
    mut client: TcpStream,
    target: &str,
    ca: &Ca,
    hook: &dyn InterceptHook,
    gost: Option<&GostFallback>,
    routes: &RouteCache,
) -> anyhow::Result<()> {
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("bad CONNECT target: {target}"))?;
    let host = host.to_string();
    let port: u16 = port.parse()?;

    consume_headers_until_blank(&mut client)?;
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;

    let (cert_pem, key_pem) = ca.leaf_for(&host)?;
    let server_config = build_server_config(&cert_pem, &key_pem)?;
    let mut client_conn = rustls::ServerConnection::new(Arc::new(server_config))?;
    let mut client_tls = rustls::Stream::new(&mut client_conn, &mut client);

    loop {
        let mut request = Vec::new();
        if !read_one_http_message(&mut client_tls, &mut request)? {
            break; // клиент закрыл туннель, дальше запросов не будет
        }

        let outcome = hook.on_request(&host, port, &request);
        let Some(request) = outcome.bytes else {
            continue; // drop
        };

        let response = send_to_target(&host, port, &request, gost, routes)?;
        hook.on_response(outcome.id, &host, port, &response);

        client_tls.write_all(&response)?;
    }
    Ok(())
}

/// Сначала смотрим в `routes` — если для этого host:port уже известно,
/// каким путём получилось в прошлый раз, идём сразу туда, без пробного
/// прямого TLS на каждый запрос (это и было источником лишней задержки
/// при интерактивном браузинге ГОСТ-only хостов). Но кэш — это подсказка,
/// а не гарантия: если закешированный маршрут вдруг перестал работать
/// (сеть моргнула, конфигурация хоста поменялась), не возвращаем ошибку
/// сразу, а перепробуем всё с нуля — отказоустойчивость важнее
/// сэкономленной попытки.
fn send_to_target(
    host: &str,
    port: u16,
    request: &[u8],
    gost: Option<&GostFallback>,
    routes: &RouteCache,
) -> anyhow::Result<Vec<u8>> {
    match routes.get(host, port) {
        Some(Route::Direct) => {
            if let Ok(response) = send_to_target_tls(host, port, request) {
                return Ok(response);
            }
        }
        Some(Route::Gost) => {
            if let Some(gost) = gost {
                if let Ok(response) = call_gost(gost, host, port, request) {
                    return Ok(response);
                }
            }
        }
        None => {}
    }
    probe_and_route(host, port, request, gost, routes)
}

/// Полный проход без оглядки на кэш: сначала обычный TLS (rustls,
/// стандартные cipher suite). Если он не проходит (нет общего cipher
/// suite, отказ хендшейка и т.п. — типичный симптом ГОСТ-only цели), при
/// наличии `gost` — ретрай через VM/ГОСТ. Автоматически, без ручного
/// списка хостов: пользователь работает с большим scope, размечать
/// заранее, где ГОСТ, а где нет — не вариант. Результат (в случае успеха)
/// запоминается в `routes` на будущее.
fn probe_and_route(
    host: &str,
    port: u16,
    request: &[u8],
    gost: Option<&GostFallback>,
    routes: &RouteCache,
) -> anyhow::Result<Vec<u8>> {
    match send_to_target_tls(host, port, request) {
        Ok(response) => {
            routes.set(host, port, Route::Direct);
            Ok(response)
        }
        Err(direct_err) => {
            let Some(gost) = gost else { return Err(direct_err) };
            eprintln!("прямой TLS до {host}:{port} не удался ({direct_err}), пробую через ГОСТ");
            let response = call_gost(gost, host, port, request)
                .map_err(|gost_err| anyhow::anyhow!("прямой TLS: {direct_err}; ГОСТ тоже не удался: {gost_err}"))?;
            routes.set(host, port, Route::Gost);
            Ok(response)
        }
    }
}

fn call_gost(gost: &GostFallback, host: &str, port: u16, request: &[u8]) -> std::io::Result<Vec<u8>> {
    match gost {
        GostFallback::Vm { ssh_target, openssl_cnf_path, timeout } => {
            connectors::send_raw_vm_gost(ssh_target, openssl_cnf_path, host, port, request, *timeout)
        }
        GostFallback::Host { openssl_cnf_path, timeout } => {
            connectors::send_raw_host_gost(openssl_cnf_path, host, port, request, *timeout)
        }
    }
}

/// Обычный http://: абсолютный URI прямо в строке запроса, без CONNECT и
/// TLS вообще. Одноразовый (без keep-alive цикла, в отличие от HTTPS-
/// туннеля) — для MVP этого достаточно, основной трафик всё равно HTTPS.
fn handle_plain_http(mut client: TcpStream, method: &str, target: &str, hook: &dyn InterceptHook) -> anyhow::Result<()> {
    let (host, port, path) = parse_absolute_uri(target)
        .ok_or_else(|| anyhow::anyhow!("unsupported proxy request target: {target}"))?;

    let mut request = format!("{method} {path} HTTP/1.1\r\n").into_bytes();
    read_headers_and_body_into(&mut client, &mut request)?;

    let outcome = hook.on_request(&host, port, &request);
    let Some(request) = outcome.bytes else {
        return Ok(()); // drop
    };

    let response = send_to_target_plain(&host, port, &request)?;
    hook.on_response(outcome.id, &host, port, &response);

    client.write_all(&response)?;
    Ok(())
}

/// `http://host[:port]/path` -> (host, port, "/path"). По умолчанию порт 80.
fn parse_absolute_uri(target: &str) -> Option<(String, u16, String)> {
    let rest = target.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (authority.to_string(), 80u16),
    };
    Some((host, port, path))
}

fn send_to_target_tls(host: &str, port: u16, request: &[u8]) -> anyhow::Result<Vec<u8>> {
    let target_config = build_client_config();
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())?;
    let mut target_conn = rustls::ClientConnection::new(Arc::new(target_config), server_name)?;
    let mut target_sock = TcpStream::connect((host, port))?;
    target_sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut target_tls = rustls::Stream::new(&mut target_conn, &mut target_sock);
    target_tls.write_all(request)?;
    read_with_idle_timeout(&mut target_tls)
}

fn send_to_target_plain(host: &str, port: u16, request: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut target_sock = TcpStream::connect((host, port))?;
    target_sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    target_sock.write_all(request)?;
    read_with_idle_timeout(&mut target_sock)
}

/// Цель может держать keep-alive и не закрывать соединение — read_to_end
/// тогда висел бы вечно. Читаем, пока не наступит тишина read_timeout (тот
/// же приём, что в connectors::send_raw_tls).
fn read_with_idle_timeout(stream: &mut impl Read) -> anyhow::Result<Vec<u8>> {
    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(response)
}

/// Дочитывает CONNECT-заголовки и отбрасывает их (для туннеля они не
/// нужны — используется только "host:port" из самой CONNECT-строки).
fn consume_headers_until_blank(stream: &mut impl Read) -> anyhow::Result<()> {
    loop {
        let line = read_line_raw(stream)?;
        if line.is_empty() || line == "\r\n" {
            break;
        }
    }
    Ok(())
}

/// Дочитывает заголовки (до пустой строки) и тело по Content-Length,
/// дописывая сырые байты в `out`. Используется для plain-http ветки, где
/// первая строка уже переписана в origin-form и лежит в `out` заранее.
fn read_headers_and_body_into(stream: &mut impl Read, out: &mut Vec<u8>) -> anyhow::Result<()> {
    loop {
        let line = read_line_raw(stream)?;
        out.extend_from_slice(line.as_bytes());
        if line.is_empty() || line == "\r\n" {
            break;
        }
    }
    let parsed = raw_http::parse_request(out);
    let content_length: usize = parsed
        .header_values("content-length")
        .first()
        .and_then(|v| std::str::from_utf8(v).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    if content_length > 0 {
        let mut body = vec![0u8; content_length];
        stream.read_exact(&mut body)?;
        out.extend_from_slice(&body);
    }
    Ok(())
}

/// Байт за байтом, без BufReader: буферизованный ридер может утащить в
/// свой внутренний буфер байты TLS ClientHello, если клиент отправит их не
/// дожидаясь "200 Connection Established" — они бы потерялись при
/// переключении на прямое чтение для хендшейка.
fn read_line_raw(stream: &mut impl Read) -> anyhow::Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            break;
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
}

/// Читает один HTTP-запрос от клиента: заголовки до пустой строки + тело по
/// Content-Length (если есть). Возвращает false, если туннель закрылся
/// чисто (EOF) до начала следующего запроса — это конец цикла, не ошибка.
/// Для MVP-прозрачного relay этого достаточно; произвольный raw ввод
/// (chunked/дубликаты) редактируется уже на уровне raw_http, когда
/// появится интерактивный intercept.
fn read_one_http_message(stream: &mut impl Read, out: &mut Vec<u8>) -> anyhow::Result<bool> {
    let mut buf = [0u8; 4096];
    loop {
        let n = match stream.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            return Ok(false);
        }
        out.extend_from_slice(&buf[..n]);
        if let Some(headers_end) = find_headers_end(out) {
            let parsed = raw_http::parse_request(out);
            let content_length: usize = parsed
                .header_values("content-length")
                .first()
                .and_then(|v| std::str::from_utf8(v).ok())
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(0);
            if out.len() >= headers_end + content_length {
                return Ok(true);
            }
        }
    }
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn build_server_config(cert_pem: &str, key_pem: &str) -> anyhow::Result<rustls::ServerConfig> {
    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?
        .ok_or_else(|| anyhow::anyhow!("no private key in leaf pem"))?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(config)
}

fn build_client_config() -> rustls::ClientConfig {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}
