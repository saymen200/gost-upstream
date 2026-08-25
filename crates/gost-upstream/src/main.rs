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
/// локальным CA, а настоящий ГОСТ TLS 1.2-хендшейк до цели делает VM,
/// куда мы стучимся по SSH.
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

    /// SSH-адрес VM с собранным gost-engine, например user@vm-host. Если
    /// не задан — прокси работает в режиме обычного MITM без ГОСТ-фолбэка
    /// (полезно для проверки самого прокси/сертификатов без VM).
    #[arg(long)]
    ssh_target: Option<String>,

    /// Путь НА VM к openssl.cnf с загруженным gost-engine (см. README —
    /// движок должен грузиться через конфиг, не через флаг -engine).
    #[arg(long, default_value = "~/gost.cnf")]
    openssl_cnf: String,

    /// Сколько ждать ответ от VM/ГОСТ-цели, прежде чем считать запрос
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

    let gost = args.ssh_target.map(|ssh_target| GostFallback {
        ssh_target,
        openssl_cnf_path: args.openssl_cnf,
        timeout: Duration::from_secs(args.gost_timeout_secs),
    });
    match &gost {
        Some(g) => println!("ГОСТ-фолбэк через {} (openssl.cnf: {})", g.ssh_target, g.openssl_cnf_path),
        None => println!("ГОСТ-фолбэк выключен (--ssh-target не задан) — обычный MITM без ГОСТ"),
    }

    println!(
        "Слушаю {} — укажите этот адрес как upstream proxy в Burp",
        args.listen
    );
    proxy::run(&args.listen, ca, Arc::new(PassThrough), gost)
}
