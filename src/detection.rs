use std::collections::HashSet;

pub const NAME_LENGTH_THRESHOLD: usize = 100;
pub const ENTROPY_THRESHOLD: f64 = 7.2;

lazy_static::lazy_static! {
    pub static ref SAFE_STRING_CACHE: std::sync::Mutex<std::collections::HashSet<String>> = {
        let capacity = crate::config::SYSTEM_CONFIG.safe_string_cache_capacity;
        std::sync::Mutex::new(std::collections::HashSet::with_capacity(capacity))
    };

    pub static ref OBFUSCATED_NAME_CACHE: std::sync::Mutex<std::collections::HashSet<String>> = {
        let capacity = crate::config::SYSTEM_CONFIG.obfuscated_name_cache_capacity;
        std::sync::Mutex::new(std::collections::HashSet::with_capacity(capacity))
    };

    pub static ref SUSPICIOUS_DOMAINS: HashSet<String> = {
        [
            "discord.com",
            "discordapp.com",
            "pastebin.com",
        ]
        .iter()
        .map(|&s| s.to_lowercase())
        .collect()
    };
}

pub fn is_cached_safe_string(s: &str) -> bool {
    if let Ok(cache) = SAFE_STRING_CACHE.lock() {
        return cache.contains(s);
    }
    false
}

pub fn cache_safe_string(s: &str) -> bool {
    if let Ok(mut cache) = SAFE_STRING_CACHE.lock() {
        return cache.insert(s.to_string());
    }
    false
}

pub fn calculate_detection_hash(data: &[u8]) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();

    if data.len() > 1024 {
        let start = &data[..512];
        let middle = &data[data.len() / 2 - 256..data.len() / 2 + 256];
        let end = &data[data.len() - 512..];

        start.hash(&mut hasher);
        middle.hash(&mut hasher);
        end.hash(&mut hasher);
        (data.len() as u64).hash(&mut hasher);
    } else {
        data.hash(&mut hasher);
    }

    hasher.finish()
}
