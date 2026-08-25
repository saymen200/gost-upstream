use clap::Parser;
use proxy::ca::Ca;
use proxy::hook::PassThrough;
use proxy::GostFallback;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// GOST TLS upstream proxy для Burp Suite (или любого инструмента с
/// поддержкой upstream-прокси). Сам инструмент ГОСТ-крипто никогда не
/// касается: он видит обычный TLS-сертификат на нужное имя, подписанный
/// локальным CA, а настоящий ГОСТ TLS 1.2-хендшейк до цели делает
/// gost-engine — либо на отдельной VM по SSH (`--ssh-target`), либо прямо
/// на этой машине (`--host-gost`).
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Адрес, на котором слушать входящие соединения (сюда указываем Burp
    /// как upstream proxy: Settings → Network → Connections → Upstream
    /// Proxy Servers).
    #[arg(long, default_value = "127.0.0.1:8888")]
    listen: String,

    /// Путь к сертификату CA (генерируется при первом запуске, если файла
    /// ещё нет). Импортировать в Burp: Settings → Network → TLS → Custom
    /// CA certificates.
    #[arg(long, default_value = "gost-upstream-ca.pem")]
    ca_cert: PathBuf,

    /// Путь к приватному ключу CA.
    #[arg(long, default_value = "gost-upstream-ca-key.pem")]
    ca_key: PathBuf,

    /// Режим VM: SSH-адрес машины с собранным gost-engine, например
    /// user@vm-host. Крипто-плечо изолировано на отдельной машине.
    /// Взаимоисключающе с --host-gost.
    #[arg(long, conflicts_with = "host_gost")]
    ssh_target: Option<String>,

    /// Режим host: gost-engine стоит прямо на этой машине, openssl
    /// s_client запускается локально, без SSH/VM. Взаимоисключающе с
    /// --ssh-target.
    #[arg(long, conflicts_with = "ssh_target")]
    host_gost: bool,

    /// Путь к openssl.cnf с загруженным gost-engine — НА VM в режиме
    /// --ssh-target, или на этой машине в режиме --host-gost (см. README —
    /// движок должен грузиться через конфиг, не через флаг -engine).
    #[arg(long, default_value = "~/gost.cnf")]
    openssl_cnf: String,

    /// Сколько ждать ответ от ГОСТ-цели, прежде чем считать запрос
    /// проваленным.
    #[arg(long, default_value_t = 20)]
    gost_timeout_secs: u64,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let ca = Arc::new(Ca::load_or_generate(&args.ca_cert, &args.ca_key)?);
    println!(
        "CA сертификат: {} — импортируйте в Burp (Settings → Network → TLS → Custom CA certificates)",
        args.ca_cert.display()
    );

    let timeout = Duration::from_secs(args.gost_timeout_secs);
    let gost = if let Some(ssh_target) = args.ssh_target {
        println!("ГОСТ-фолбэк: VM через {ssh_target} (openssl.cnf: {})", args.openssl_cnf);
        Some(GostFallback::Vm { ssh_target, openssl_cnf_path: args.openssl_cnf, timeout })
    } else if args.host_gost {
        println!("ГОСТ-фолбэк: локально на этой машине (openssl.cnf: {})", args.openssl_cnf);
        Some(GostFallback::Host { openssl_cnf_path: args.openssl_cnf, timeout })
    } else {
        println!("ГОСТ-фолбэк выключен (--ssh-target/--host-gost не заданы) — обычный MITM без ГОСТ");
        None
    };

    println!(
        "Слушаю {} — укажите этот адрес как upstream proxy в Burp",
        args.listen
    );
    proxy::run(&args.listen, ca, Arc::new(PassThrough), gost)
}
