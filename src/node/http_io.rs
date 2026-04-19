use super::*;

pub(super) fn parse_http_content_length(header: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(header).ok()?;
    for line in text.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            return value.trim().parse().ok();
        }
    }
    None
}

pub(super) fn parse_http_header_value<'a>(header: &'a [u8], name: &str) -> Option<&'a str> {
    let text = std::str::from_utf8(header).ok()?;
    for line in text.lines() {
        let Some((candidate, value)) = line.split_once(':') else {
            continue;
        };
        if candidate.eq_ignore_ascii_case(name) {
            return Some(value.trim());
        }
    }
    None
}

pub(super) fn parse_forwarded_for(header: &[u8]) -> Option<String> {
    parse_http_header_value(header, "x-forwarded-for").and_then(|value| {
        let first = value
            .split(',')
            .map(str::trim)
            .find(|candidate| !candidate.is_empty())?;
        Some(first.to_string())
    })
}

pub(super) async fn read_rpc_request(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut chunk = vec![0u8; 8192];
    let mut raw = Vec::new();

    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() > MAX_RPC_REQUEST_BYTES {
            anyhow::bail!("rpc request exceeded size limit");
        }

        let is_http = raw.starts_with(b"POST") || raw.starts_with(b"GET");
        if !is_http {
            break;
        }

        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            let split = pos + 4;
            if split > MAX_RPC_HEADER_BYTES {
                anyhow::bail!("rpc headers exceeded size limit");
            }
            let content_length = parse_http_content_length(&raw[..split]).unwrap_or(0);
            if content_length > MAX_RPC_BODY_BYTES {
                anyhow::bail!("rpc body exceeded size limit");
            }
            if raw.len() >= split + content_length {
                break;
            }
        }
    }

    Ok(raw)
}

pub(super) async fn read_http_headers<S>(stream: &mut S) -> anyhow::Result<(Vec<u8>, Vec<u8>)>
where
    S: AsyncReadExt + Unpin,
{
    let mut chunk = vec![0u8; 4096];
    let mut raw = Vec::new();

    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            anyhow::bail!("connection closed before handshake completed");
        }
        raw.extend_from_slice(&chunk[..n]);

        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            let split = pos + 4;
            let leftover = raw[split..].to_vec();
            raw.truncate(split);
            return Ok((raw, leftover));
        }

        if raw.len() > 16_384 {
            anyhow::bail!("handshake headers exceeded 16 KiB limit");
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_header_value_is_case_insensitive() {
        let header = b"POST / HTTP/1.1\r\nX-Forwarded-For: 198.51.100.10\r\n\r\n";
        assert_eq!(
            super::parse_http_header_value(header, "x-forwarded-for"),
            Some("198.51.100.10")
        );
    }

    #[test]
    fn parse_forwarded_for_takes_first_forwarded_ip() {
        let header = b"POST / HTTP/1.1\r\nX-Forwarded-For: 198.51.100.10, 203.0.113.7\r\n\r\n";
        assert_eq!(
            super::parse_forwarded_for(header),
            Some("198.51.100.10".to_string())
        );
    }
}
