/// Корректный chunk: `{hex-размер}\r\n{данные}\r\n`.
pub fn chunk(data: &[u8]) -> Vec<u8> {
    let mut out = format!("{:x}\r\n", data.len()).into_bytes();
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
    out
}

/// Chunk с произвольной (в т.ч. кривой/с расширением) строкой размера —
/// для случаев, когда нужен размер не в виде честного hex-числа.
pub fn chunk_with_size_line(size_line: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(size_line);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
    out
}

pub const FINAL_CHUNK: &[u8] = b"0\r\n\r\n";

/// Собирает chunked-тело руками, без скрытой магии: что запушили — то и
/// будет в итоговых байтах, в том числе можно завершить без финального
/// чанка или дописать что угодно после него (например, второй запрос
/// для десинхронизации).
#[derive(Debug, Default)]
pub struct ChunkedBodyBuilder {
    out: Vec<u8>,
}

impl ChunkedBodyBuilder {
    pub fn new() -> Self {
        Self { out: Vec::new() }
    }

    pub fn push_chunk(mut self, data: &[u8]) -> Self {
        self.out.extend_from_slice(&chunk(data));
        self
    }

    pub fn push_chunk_with_size_line(mut self, size_line: &[u8], data: &[u8]) -> Self {
        self.out.extend_from_slice(&chunk_with_size_line(size_line, data));
        self
    }

    /// Произвольные сырые байты без какой-либо оболочки — эскейп-люк.
    pub fn push_raw(mut self, bytes: &[u8]) -> Self {
        self.out.extend_from_slice(bytes);
        self
    }

    pub fn finish_with_final_chunk(mut self) -> Vec<u8> {
        self.out.extend_from_slice(FINAL_CHUNK);
        self.out
    }

    /// Без "0\r\n\r\n" — для PoC, где нужно намеренно не завершать тело.
    pub fn finish_without_final_chunk(self) -> Vec<u8> {
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_chunk_format() {
        assert_eq!(chunk(b"abc"), b"3\r\nabc\r\n".to_vec());
    }

    #[test]
    fn builder_matches_manual_concat() {
        let built = ChunkedBodyBuilder::new()
            .push_chunk(b"foo")
            .push_chunk(b"bar")
            .finish_with_final_chunk();
        let expected = [chunk(b"foo"), chunk(b"bar"), FINAL_CHUNK.to_vec()].concat();
        assert_eq!(built, expected);
    }

    #[test]
    fn smuggled_second_request_after_final_chunk() {
        let smuggled = b"GET /admin HTTP/1.1\r\nHost: x\r\n\r\n";
        let built = ChunkedBodyBuilder::new()
            .push_chunk(b"0")
            .finish_with_final_chunk()
            .into_iter()
            .chain(smuggled.iter().copied())
            .collect::<Vec<u8>>();
        assert!(built.ends_with(smuggled));
    }
}
