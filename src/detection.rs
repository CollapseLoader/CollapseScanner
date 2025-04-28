pub const NAME_LENGTH_THRESHOLD: usize = 100;
pub const ENTROPY_THRESHOLD: f64 = 7.2;
pub const SUSPICIOUS_CHAR_THRESHOLD: usize = 3;

pub const MIN_STRING_LENGTH: usize = 5;
pub const MAX_PATTERN_CHECK_LENGTH: usize = 4096;
pub const RESULT_CACHE_SIZE: usize = 2048;

pub fn contains_network_indicators(s: &str) -> bool {
    s.contains("http")
        || s.contains("www.")
        || s.contains("://")
        || s.contains(".com")
        || s.contains(".net")
        || s.contains(".org")
        || s.contains("192.168.")
        || s.contains("10.0.")
        || s.contains("127.0.0")
}

pub fn contains_crypto_indicators(s: &str) -> bool {
    s.contains("aes")
        || s.contains("rsa")
        || s.contains("des")
        || s.contains("sha")
        || s.contains("md5")
        || s.contains("crypt")
        || s.contains("key")
        || s.contains("hash")
        || s.contains("password")
}

pub fn contains_malicious_indicators(s: &str) -> bool {
    s.contains("backdoor")
        || s.contains("exploit")
        || s.contains("payload")
        || s.contains("inject")
        || s.contains("exec")
        || s.contains("socket")
        || s.contains("download")
        || s.contains("jndi")
        || s.contains("ldap")
}

pub fn is_obfuscated_name(name: &str) -> bool {
    if name.len() <= 2 && name != "of" && name != "to" && name != "at" && name != "id" {
        return true;
    }

    let chars: Vec<_> = name.chars().collect();
    if chars.len() >= 3 {
        let repeats = chars
            .windows(3)
            .filter(|w| w[0] == w[1] && w[1] == w[2])
            .count();
        if repeats > 0 {
            return true;
        }
    }

    name.contains("$_")
        || name.contains("$$")
        || name.contains("III")
        || name.contains("lll")
        || name.contains("OOO")
        || name.matches('$').count() > 2
}

lazy_static::lazy_static! {

    pub static ref SAFE_STRING_CACHE: std::sync::Mutex<std::collections::HashSet<String>> =
        std::sync::Mutex::new(std::collections::HashSet::with_capacity(1000));


    pub static ref OBFUSCATED_NAME_CACHE: std::sync::Mutex<std::collections::HashSet<String>> =
        std::sync::Mutex::new(std::collections::HashSet::with_capacity(500));
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

pub fn should_analyze_string(s: &str) -> bool {
    if s.len() < MIN_STRING_LENGTH {
        return false;
    }

    true
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
