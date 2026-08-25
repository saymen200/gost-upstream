use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

pub mod vm_gost;
pub use vm_gost::{send_raw_host_gost, send_raw_vm_gost};

/// Отправляет `request` как есть (побайтово, без какой-либо нормализации)
/// через обычный TLS и собирает всё, что прилетело в ответ в течение
/// `read_timeout`. Таймаут вместо read_to_end() специально: соединение
/// может остаться keep-alive, а нам как раз интересно увидеть "лишние"
/// байты (второй ответ / сдвиг) — признак desync.
pub fn send_raw_tls(
    host: &str,
    port: u16,
    request: &[u8],
    read_timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let mut sock = TcpStream::connect((host, port))?;
    sock.set_read_timeout(Some(read_timeout))?;

    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(request)?;

    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break
            }
            Err(e) => return Err(e),
        }
    }
    Ok(response)
}
