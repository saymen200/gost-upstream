use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

/// Cipher suite'ы, которые реально отдаёт `openssl ciphers` после того как
/// gost-engine загружен ЧЕРЕЗ openssl.cnf (а не флагом -engine — известная
/// проблема openssl/openssl#5809: -engine подключается позже, чем
/// сканируются доступные cipher suite, и они остаются выключены).
const GOST_CIPHERS: &str = "GOST2012-MAGMA-MAGMAOMAC:GOST2012-KUZNYECHIK-KUZNYECHIKOMAC:\
LEGACY-GOST2012-GOST8912-GOST8912:IANA-GOST2012-GOST8912-GOST8912:GOST2001-GOST89-GOST89";

/// Отправляет `request` побайтово на `target_host:target_port` через
/// настоящий ГОСТ TLS 1.2, поднятый на VM (`ssh_target`, например
/// "user@vm-host"). Крипто-плечо целиком изолировано на VM — сюда,
/// на хост, идёт только plain-байтовый поток через SSH exec-канал.
///
/// Транспорт байт-прозрачен по конструкции: SSH exec без `-t` (без pty) не
/// трогает данные, `openssl s_client -quiet -ign_eof` не парсит HTTP — он
/// просто шифрует stdin в сокет и расшифровывает сокет в stdout.
///
/// `openssl_cnf_path` — путь на VM к конфигу с `dynamic_path` на собранный
/// gost.so (см. INSTALL.md gost-engine, секция "How to Configure").
///
/// `timeout` — верхняя граница на весь процесс (страховка, если цель вообще
/// не отвечает). Реальное завершение чтения — по тишине на stdout, см. ниже.
pub fn send_raw_vm_gost(
    ssh_target: &str,
    openssl_cnf_path: &str,
    target_host: &str,
    target_port: u16,
    request: &[u8],
    timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    let remote_cmd = format!(
        "OPENSSL_CONF={openssl_cnf_path} openssl s_client -connect {target_host}:{target_port} \
         -cipher {GOST_CIPHERS} -tls1_2 -quiet -ign_eof 2>/dev/null"
    );

    let mut child = Command::new("timeout")
        .arg(format!("{}s", timeout.as_secs()))
        .arg("ssh")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg(ssh_target)
        .arg(remote_cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    child.stdin.take().unwrap().write_all(request)?;

    // `-ign_eof` намеренно не закрывает stdout сам — единственный способ
    // раньше был дождаться, пока его прибьёт внешний `timeout`, отсюда
    // фиксированная задержка на КАЖДЫЙ запрос. Вместо этого читаем в фоновом
    // потоке и решаем "ответ закончился" по паузе (тишина), а не по EOF.
    let mut stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match stdout.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Первый байт может идти дольше (SSH-хендшейк + ГОСТ TLS-хендшейк на
    // VM), поэтому для него окно шире; после того как данные пошли — пауза
    // короче, обычно достаточно уже для "ответ дописан".
    let mut response = Vec::new();
    if let Ok(chunk) = rx.recv_timeout(Duration::from_secs(10)) {
        response.extend_from_slice(&chunk);
        while let Ok(chunk) = rx.recv_timeout(Duration::from_millis(800)) {
            response.extend_from_slice(&chunk);
        }
    }

    // Не ждём child.wait() здесь — это снова была бы блокировка до общего
    // timeout. Реапим в фоне, чтобы не плодить зомби-процессы.
    thread::spawn(move || {
        let _ = child.wait();
    });

    Ok(response)
}
