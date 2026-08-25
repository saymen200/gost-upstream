use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

/// Корневой CA для MITM: один раз генерируется/грузится с диска, пользователь
/// импортирует `cert_pem()` в браузер как доверенный корневой сертификат.
/// Листовые сертификаты на лету подписываются этим CA под конкретный host —
/// хост всегда известен заранее из CONNECT-строки, SNI-угадывание не нужно.
pub struct Ca {
    key_pair: KeyPair,
    cert: Certificate,
    cert_pem: String,
    leaf_cache: Mutex<HashMap<String, (String, String)>>, // host -> (cert_pem, key_pem)
}

impl Ca {
    pub fn load_or_generate(cert_path: &Path, key_path: &Path) -> anyhow::Result<Self> {
        if cert_path.exists() && key_path.exists() {
            let cert_pem = fs::read_to_string(cert_path)?;
            let key_pem = fs::read_to_string(key_path)?;
            let key_pair = KeyPair::from_pem(&key_pem)?;
            // Пересобираем self-signed Certificate из тех же params+ключа —
            // не обязано побайтово совпадать с файлом на диске, важно только,
            // чтобы issuer DN/key совпадали с тем, что доверяет браузер.
            let params = CertificateParams::from_ca_cert_pem(&cert_pem)?;
            let cert = params.self_signed(&key_pair)?;
            return Ok(Ca { key_pair, cert, cert_pem, leaf_cache: Mutex::new(HashMap::new()) });
        }

        let mut params = CertificateParams::new(Vec::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "gost-upstream local CA (dev, do not trust globally)");
        dn.push(DnType::OrganizationName, "gost-upstream");
        params.distinguished_name = dn;

        let key_pair = KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;
        let cert_pem = cert.pem();

        if let Some(parent) = cert_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(cert_path, &cert_pem)?;
        fs::write(key_path, key_pair.serialize_pem())?;

        Ok(Ca { key_pair, cert, cert_pem, leaf_cache: Mutex::new(HashMap::new()) })
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Возвращает (cert_pem, key_pem) листового сертификата для `host`,
    /// генерируя и кэшируя при первом обращении.
    pub fn leaf_for(&self, host: &str) -> anyhow::Result<(String, String)> {
        if let Some(pair) = self.leaf_cache.lock().unwrap().get(host) {
            return Ok(pair.clone());
        }

        let mut leaf_params = CertificateParams::new(vec![host.to_string()])?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        leaf_params.distinguished_name = dn;

        let leaf_key = KeyPair::generate()?;
        let leaf_cert = leaf_params.signed_by(&leaf_key, &self.cert, &self.key_pair)?;

        let pair = (leaf_cert.pem(), leaf_key.serialize_pem());
        self.leaf_cache.lock().unwrap().insert(host.to_string(), pair.clone());
        Ok(pair)
    }
}
