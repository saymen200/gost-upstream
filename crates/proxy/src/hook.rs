/// Точка расширения между сетевым ядром прокси (синхронное, ничего не
/// знает про web/WS/tokio) и тем, кто хочет видеть/приостанавливать
/// трафик (`server`). Реализация вызывается прямо из потока, который
/// держит TLS-соединение с браузером, поэтому может блокироваться —
/// именно так работает пауза "intercept": поток буквально ждёт решения.
pub trait InterceptHook: Send + Sync {
    /// Запрос готов уйти к цели. `id` в возвращённом значении передаётся
    /// потом в `on_response` — так реализация может связать ответ с тем
    /// же запросом (нужно для истории/UI, hook сам решает, что такое id).
    fn on_request(&self, host: &str, port: u16, request: &[u8]) -> InterceptedRequest;

    /// Ответ от цели получен (после отправки, для отображения/истории).
    fn on_response(&self, id: u64, host: &str, port: u16, response: &[u8]);
}

pub struct InterceptedRequest {
    pub id: u64,
    /// `Some(bytes)` — отправить именно эти байты (можно отредактированную
    /// копию), `None` — не отправлять вообще (drop).
    pub bytes: Option<Vec<u8>>,
}

/// Ничего не делает — прежнее прозрачное поведение прокси без hook'а.
pub struct PassThrough;

impl InterceptHook for PassThrough {
    fn on_request(&self, _host: &str, _port: u16, request: &[u8]) -> InterceptedRequest {
        InterceptedRequest { id: 0, bytes: Some(request.to_vec()) }
    }
    fn on_response(&self, _id: u64, _host: &str, _port: u16, _response: &[u8]) {}
}
