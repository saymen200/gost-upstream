use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
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
/// `openssl_cnf_path` — путь НА VM к конфигу с `dynamic_path` на собранный
/// gost.so (см. INSTALL.md gost-engine, секция "How to Configure").
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

    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes").arg(ssh_target).arg(remote_cmd);
    run_with_deadline(cmd, request, timeout)
}

/// То же самое, но без VM/SSH — `openssl s_client` с gost-engine запускается
/// прямо на той же машине, где крутится сам инструмент. Годится, когда
/// изоляция крипто-плеча в отдельную VM не нужна (это уже не CryptoPro,
/// а открытый gost-engine — ставить его на хост безопаснее, чем закрытый
/// проприетарный CSP). `openssl_cnf_path` — путь на ЭТОЙ машине.
pub fn send_raw_host_gost(
    openssl_cnf_path: &str,
    target_host: &str,
    target_port: u16,
    request: &[u8],
    timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    let mut cmd = Command::new("openssl");
    cmd.env("OPENSSL_CONF", openssl_cnf_path)
        .arg("s_client")
        .arg("-connect")
        .arg(format!("{target_host}:{target_port}"))
        .arg("-cipher")
        .arg(GOST_CIPHERS)
        .arg("-tls1_2")
        .arg("-quiet")
        .arg("-ign_eof");
    run_with_deadline(cmd, request, timeout)
}

/// Общая часть для vm- и host-режимов: спавнит `cmd` (уже настроенную —
/// либо `ssh ... 'openssl s_client ...'`, либо `openssl s_client ...`
/// напрямую), пишет `request` в stdin, читает ответ по idle-cutoff и
/// обеспечивает верхнюю границу по времени через `child.kill()` из
/// отдельного потока (не через внешнюю утилиту `timeout` — той нет на
/// Windows).
fn run_with_deadline(mut cmd: Command, request: &[u8], timeout: Duration) -> std::io::Result<Vec<u8>> {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    child.stdin.take().unwrap().write_all(request)?;

    // `-ign_eof` намеренно не закрывает stdout сам — реальный сигнал "ответ
    // закончился" это пауза на stdout, а не EOF (см. read-loop ниже). А
    // `timeout` — верхняя граница на случай, если цель вообще не отвечает:
    // без внешней команды `timeout`, отдельный поток убивает процесс сам,
    // если тот не уложился в дедлайн.
    let child: Arc<Mutex<Child>> = Arc::new(Mutex::new(child));
    {
        let child = child.clone();
        thread::spawn(move || {
            thread::sleep(timeout);
            let _ = child.lock().unwrap().kill();
        });
    }

    let mut stdout = child.lock().unwrap().stdout.take().unwrap();
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

    // Первый байт может идти дольше (SSH/ГОСТ TLS-хендшейк), поэтому для
    // него окно шире; после того как данные пошли — пауза короче, обычно
    // уже достаточно, чтобы считать "ответ дописан".
    let mut response = Vec::new();
    if let Ok(chunk) = rx.recv_timeout(Duration::from_secs(10)) {
        response.extend_from_slice(&chunk);
        while let Ok(chunk) = rx.recv_timeout(Duration::from_millis(800)) {
            response.extend_from_slice(&chunk);
        }
    }

    // Не ждём завершения здесь — это снова была бы блокировка. Реапим в
    // фоне, чтобы не плодить зомби-процессы (актуально на Unix; на Windows
    // просто освобождает handle).
    thread::spawn(move || {
        let _ = child.lock().unwrap().wait();
    });

    Ok(response)
}
