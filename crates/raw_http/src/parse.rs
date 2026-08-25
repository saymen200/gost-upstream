use crate::request::{HeaderEntry, RawHeader, RawRequest};

/// Разбивает `input` на (содержимое строки без переноса, сами байты
/// переноса, остаток). Понимает и CRLF, и голый LF. Если переноса нет —
/// вся строка уходит в content, ending пустой (последняя частичная строка).
fn next_line(input: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    if input.is_empty() {
        return None;
    }
    for i in 0..input.len() {
        if input[i] == b'\n' {
            let ending_start = if i > 0 && input[i - 1] == b'\r' { i - 1 } else { i };
            return Some((&input[..ending_start], &input[ending_start..=i], &input[i + 1..]));
        }
    }
    Some((input, b"", &input[input.len()..]))
}

fn parse_header_line(content: &[u8], ending: &[u8]) -> HeaderEntry {
    match content.iter().position(|&b| b == b':') {
        Some(colon) => HeaderEntry::Header(RawHeader {
            name: content[..colon].to_vec(),
            value: content[colon + 1..].to_vec(),
            line_ending: ending.to_vec(),
        }),
        None => {
            let mut v = content.to_vec();
            v.extend_from_slice(ending);
            HeaderEntry::Raw(v)
        }
    }
}

/// Best-effort парсинг: не падает на кривом вводе, не выбирает
/// "правильную" интерпретацию при конфликте Content-Length/Transfer-Encoding
/// (это забота вызывающего кода/attacks, не парсера). Тело — это всё, что
/// осталось после первой пустой строки, без учёта Content-Length/chunked —
/// для raw-редактора именно это и нужно: что вставили, то и уйдёт.
pub fn parse_request(input: &[u8]) -> RawRequest {
    let (request_line, request_line_ending, mut rest) =
        next_line(input).unwrap_or((b"", b"", input));

    let mut headers = Vec::new();
    let headers_terminator: Vec<u8>;
    loop {
        match next_line(rest) {
            None => {
                headers_terminator = Vec::new();
                rest = b"";
                break;
            }
            Some((content, ending, r)) => {
                if content.is_empty() {
                    headers_terminator = ending.to_vec();
                    rest = r;
                    break;
                }
                headers.push(parse_header_line(content, ending));
                rest = r;
            }
        }
    }

    RawRequest {
        request_line: request_line.to_vec(),
        request_line_ending: request_line_ending.to_vec(),
        headers,
        headers_terminator,
        body: rest.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_builder_output() {
        let req = RawRequest::new("POST", "/", "HTTP/1.1")
            .header("Host", "example.com")
            .header("Content-Length", "5")
            .body(b"hello".to_vec());
        let bytes = req.to_bytes();
        let parsed = parse_request(&bytes);
        assert_eq!(parsed.to_bytes(), bytes);
        assert_eq!(parsed.header_values("host"), vec![b" example.com".as_slice()]);
    }

    #[test]
    fn preserves_obfuscated_spacing_and_duplicates() {
        let raw = b"GET / HTTP/1.1\r\n\
Host: example.com\r\n\
Transfer-Encoding : chunked\r\n\
Transfer-Encoding: identity\r\n\
\r\n\
0\r\n\r\n";
        let parsed = parse_request(raw);
        // должно быть побайтово идентично тому, что было на входе
        assert_eq!(parsed.to_bytes(), raw.to_vec());

        let te = parsed.header_values("transfer-encoding");
        assert_eq!(te.len(), 2);
        assert_eq!(te[0], b" chunked".as_slice());
    }

    #[test]
    fn line_without_colon_is_raw_entry() {
        let raw = b"GET / HTTP/1.1\r\nnot-a-header-line\r\nHost: x\r\n\r\n";
        let parsed = parse_request(raw);
        assert_eq!(parsed.to_bytes(), raw.to_vec());
        assert!(matches!(parsed.headers[0], HeaderEntry::Raw(_)));
    }

    #[test]
    fn lf_only_request_round_trips() {
        let raw = b"GET / HTTP/1.1\nHost: example.com\n\nbody";
        let parsed = parse_request(raw);
        assert_eq!(parsed.to_bytes(), raw.to_vec());
    }
}
