use url::Url;

pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut byte_counts = [0u64; 256];
    let len = data.len() as f64;

    for &byte in data {
        byte_counts[byte as usize] += 1;
    }

    let mut entropy = 0.0;
    for &count in byte_counts.iter().filter(|&&c| c > 0) {
        let probability = count as f64 / len;

        entropy -= probability * (probability.ln() / std::f64::consts::LN_2);
    }

    entropy
}

pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        let mut truncated: String = s.chars().take(max_len.saturating_sub(3)).collect();
        truncated.push_str("...");
        truncated
    }
}

pub fn extract_domain(url_str: &str) -> String {
    let get_host = |url: Url| -> Option<String> {
        url.host_str()
            .map(|host| host.trim_start_matches("www.").to_lowercase())
    };

    if let Ok(url) = Url::parse(url_str) {
        if let Some(host) = get_host(url) {
            return host;
        }
    }

    if (!url_str.contains("://") && url_str.contains('.')) || url_str.starts_with("//") {
        let prefix = if url_str.starts_with("//") {
            "http:"
        } else {
            "http://"
        };
        let url_with_scheme = format!("{}{}", prefix, url_str);

        if let Ok(url) = Url::parse(&url_with_scheme) {
            if let Some(host) = get_host(url) {
                return host;
            }
        }
    }

    "".to_string()
}

pub fn get_simple_name(fqn: &str) -> &str {
    let name_part = fqn.strip_suffix('/').unwrap_or(fqn);

    name_part
        .rsplit(|c| c == '/' || c == '.')
        .next()
        .unwrap()
}