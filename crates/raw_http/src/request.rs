/// Заголовок, распознанный как пара name/value вокруг `:`.
/// Пробелы и регистр вокруг имени/значения не нормализуются — они часть
/// name/value как есть, потому что именно в них живёт обфускация
/// (`Transfer-Encoding : chunked`, `Transfer-Encoding:\tchunked` и т.п.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHeader {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub line_ending: Vec<u8>,
}

/// Одна строка заголовочного блока. `Raw` — эскейп-люк для строк, которые
/// вообще не влезают в форму `name: value` (например, нет двоеточия).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderEntry {
    Header(RawHeader),
    Raw(Vec<u8>),
}

/// HTTP-запрос как есть, побайтово. `to_bytes()` всегда собирает ровно то,
/// что лежит в полях — никакой автоматической починки Content-Length,
/// нормализации переносов строк и т.п. Всё это — явные действия сверху.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRequest {
    pub request_line: Vec<u8>,
    pub request_line_ending: Vec<u8>,
    pub headers: Vec<HeaderEntry>,
    /// Пустая строка, разделяющая заголовки и тело (обычно b"\r\n").
    pub headers_terminator: Vec<u8>,
    pub body: Vec<u8>,
}

/// Сравнение имени заголовка для целей поиска (header_values/remove_headers):
/// торчащие пробелы вокруг имени (обфускация вида `Transfer-Encoding :`)
/// не должны мешать найти заголовок по общепринятому имени — раз мы сами
/// не знаем, как их растолкует конкретный сервер, находим оба варианта.
/// На сериализацию (to_bytes) это не влияет — там имя всегда как в поле.
fn trim_ascii_whitespace(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(s.len());
    let end = s.iter().rposition(|b| !b.is_ascii_whitespace()).map_or(start, |e| e + 1);
    &s[start..end]
}

fn header_name_matches(name: &[u8], target: &[u8]) -> bool {
    trim_ascii_whitespace(name).eq_ignore_ascii_case(trim_ascii_whitespace(target))
}

impl RawRequest {
    pub fn new(method: &str, target: &str, version: &str) -> Self {
        let mut request_line = Vec::new();
        request_line.extend_from_slice(method.as_bytes());
        request_line.push(b' ');
        request_line.extend_from_slice(target.as_bytes());
        request_line.push(b' ');
        request_line.extend_from_slice(version.as_bytes());
        RawRequest {
            request_line,
            request_line_ending: b"\r\n".to_vec(),
            headers: Vec::new(),
            headers_terminator: b"\r\n".to_vec(),
            body: Vec::new(),
        }
    }

    /// Обычный заголовок: `.header("Host", "example.com")` -> `Host: example.com`.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        let mut v = Vec::with_capacity(value.len() + 1);
        v.push(b' ');
        v.extend_from_slice(value.as_bytes());
        self.headers.push(HeaderEntry::Header(RawHeader {
            name: name.as_bytes().to_vec(),
            value: v,
            line_ending: b"\r\n".to_vec(),
        }));
        self
    }

    /// Полный контроль над байтами name/value/line_ending — для обфускации
    /// (пробелы вокруг двоеточия, табы, дублирующиеся заголовки и т.п.).
    /// Пример: `.header_raw("Transfer-Encoding ", " chunked", "\r\n")` —
    /// пробел перед двоеточием.
    pub fn header_raw(
        mut self,
        name: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
        line_ending: impl Into<Vec<u8>>,
    ) -> Self {
        self.headers.push(HeaderEntry::Header(RawHeader {
            name: name.into(),
            value: value.into(),
            line_ending: line_ending.into(),
        }));
        self
    }

    /// Строка заголовочного блока, которая не является парой name/value
    /// вообще (нет двоеточия) — для совсем патологических PoC.
    pub fn raw_line(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.headers.push(HeaderEntry::Raw(bytes.into()));
        self
    }

    pub fn headers_terminator(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.headers_terminator = bytes.into();
        self
    }

    pub fn request_line_ending(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.request_line_ending = bytes.into();
        self
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Значения всех заголовков с данным именем (регистронезависимо),
    /// без ведущего пробела/двоеточия — как записано в поле `value`.
    pub fn header_values(&self, name: &str) -> Vec<&[u8]> {
        self.headers
            .iter()
            .filter_map(|e| match e {
                HeaderEntry::Header(h) if header_name_matches(&h.name, name.as_bytes()) => {
                    Some(h.value.as_slice())
                }
                _ => None,
            })
            .collect()
    }

    /// Убирает все заголовки с данным именем (регистронезависимо).
    pub fn remove_headers(mut self, name: &str) -> Self {
        self.headers.retain(|e| match e {
            HeaderEntry::Header(h) => !header_name_matches(&h.name, name.as_bytes()),
            HeaderEntry::Raw(_) => true,
        });
        self
    }

    /// Явный пересчёт Content-Length по текущему телу: удаляет старые
    /// Content-Length заголовки и добавляет один новый. Никогда не
    /// вызывается неявно из to_bytes()/body().
    pub fn fix_content_length(self) -> Self {
        let len = self.body.len();
        self.remove_headers("Content-Length")
            .header("Content-Length", &len.to_string())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.request_line);
        out.extend_from_slice(&self.request_line_ending);
        for entry in &self.headers {
            match entry {
                HeaderEntry::Header(h) => {
                    out.extend_from_slice(&h.name);
                    out.push(b':');
                    out.extend_from_slice(&h.value);
                    out.extend_from_slice(&h.line_ending);
                }
                HeaderEntry::Raw(bytes) => out.extend_from_slice(bytes),
            }
        }
        out.extend_from_slice(&self.headers_terminator);
        out.extend_from_slice(&self.body);
        out
    }

    pub fn to_hex(&self) -> String {
        let bytes = self.to_bytes();
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.to_bytes()).into_owned()
    }
}
