use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Direct,
    Gost,
}

/// Запоминает, каким путём успешно дошли до `host:port` в прошлый раз —
/// чтобы не пробовать обычный TLS заново на КАЖДЫЙ запрос к уже известному
/// ГОСТ-only хосту. Именно этот повторный пробный хендшейк на каждый
/// запрос и был источником лишней задержки при интерактивном браузинге:
/// раньше решение "прямой TLS или ГОСТ" принималось заново для каждого
/// отдельного запроса, а не один раз на хост.
///
/// Живёт на время работы процесса, без TTL и без записи неудач (если и
/// прямой TLS, и ГОСТ не прошли — в кэш ничего не пишем, пробуем заново
/// в следующий раз, мало ли временная сетевая проблема). Сознательное
/// упрощение: если TLS-конфигурация хоста поменяется на лету, поможет
/// только перезапуск прокси — на практике такое случается очень редко.
#[derive(Default)]
pub struct RouteCache(Mutex<HashMap<(String, u16), Route>>);

impl RouteCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, host: &str, port: u16) -> Option<Route> {
        self.0.lock().unwrap().get(&(host.to_string(), port)).copied()
    }

    pub fn set(&self, host: &str, port: u16, route: Route) {
        self.0.lock().unwrap().insert((host.to_string(), port), route);
    }
}
