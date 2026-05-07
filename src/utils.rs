use url::Url;

pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_owned()
    } else {
        let mut truncated: String = s.chars().take(max_len.saturating_sub(3)).collect();
        truncated.push_str("...");
        truncated
    }
}

pub fn extract_domain(url_str: &str) -> String {
    if let Ok(url) = Url::parse(url_str) {
        if let Some(host) = url.host_str() {
            return host.trim_start_matches("www.").to_lowercase();
        }
    }

    if (!url_str.contains("://") && url_str.contains('.')) || url_str.starts_with("//") {
        let prefixed = if url_str.starts_with("//") {
            format!("http:{}", url_str)
        } else {
            format!("http://{}", url_str)
        };

        if let Ok(url) = Url::parse(&prefixed) {
            if let Some(host) = url.host_str() {
                return host.trim_start_matches("www.").to_lowercase();
            }
        }
    }

    String::new()
}

pub fn get_simple_name(fqn: &str) -> &str {
    let name_part = fqn.strip_suffix('/').unwrap_or(fqn);
    name_part.rsplit(['/', '.']).next().unwrap_or(name_part)
}
