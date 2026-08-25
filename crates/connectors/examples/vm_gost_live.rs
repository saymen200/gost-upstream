//! Диагностика: проверить, что VM с gost-engine реально отдаёт ГОСТ TLS.
//! Usage: cargo run -p connectors --example vm_gost_live -- <ssh_target> <openssl_cnf_path> <host> <port>
//! Пример: cargo run -p connectors --example vm_gost_live -- user@vm-host ~/gost.cnf target.example.ru 443

use connectors::send_raw_vm_gost;
use raw_http::RawRequest;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!("usage: {} <ssh_target> <openssl_cnf_path> <host> <port>", args[0]);
        std::process::exit(1);
    }
    let ssh_target = &args[1];
    let openssl_cnf = &args[2];
    let target_host = &args[3];
    let target_port: u16 = args[4].parse().expect("port должен быть числом");

    let req = RawRequest::new("GET", "/", "HTTP/1.1")
        .header("Host", target_host)
        .header("Connection", "close");

    println!("--- отправляем через VM ---");
    println!("{}", req.to_string_lossy());

    match send_raw_vm_gost(
        ssh_target,
        openssl_cnf,
        target_host,
        target_port,
        &req.to_bytes(),
        Duration::from_secs(20),
    ) {
        Ok(resp) => {
            println!("--- ответ ({} байт) ---", resp.len());
            println!("{}", String::from_utf8_lossy(&resp));
        }
        Err(e) => eprintln!("ошибка: {e}"),
    }
}
