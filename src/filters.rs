use ipnet::IpNet;
use regex::Regex;
use std::collections::HashSet;
use std::net::IpAddr;

lazy_static::lazy_static! {
    /// IPv4 address regex
    pub static ref IP_REGEX: Regex = Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap();

    /// IPv6 address regex (simple/fast heuristic)
    pub static ref IPV6_REGEX: Regex = Regex::new(r"(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b").unwrap();

    /// URL detection regex (captures many common URL forms)
    pub static ref URL_REGEX: Regex = Regex::new(r#"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^
\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^
\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?«»""']))"#).unwrap();

    /// Generic malicious / suspicious pattern keywords
    pub static ref MALICIOUS_PATTERN_REGEX: Regex = Regex::new(r"(?i)\b(powershell|cmd\.exe|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|loadLibrary|socket\(|bind\(|connect\(|URL\(|URLConnection|Class\.forName|defineClass|getMethod|ldap|rmi)\b").unwrap();

    /// Known "good" links / domains
    pub static ref GOOD_LINKS: Vec<String> = vec![
        "account.mojang.com".to_string(),
        "aka.ms".to_string(),
        "apache.org".to_string(),
        "api.mojang.com".to_string(),
        "api.spiget.org".to_string(),
        "authserver.mojang.com".to_string(),
        "bugs.mojang.com".to_string(),
        "cabaletta/baritone".to_string(),
        "ci.viaversion.com".to_string(),
        "com/viaversion/".to_string(),
        "docs.advntr.dev".to_string(),
        "dominos.com".to_string(),
        "dump.viaversion.com".to_string(),
        "eclipse.org".to_string(),
        "java.sun.org".to_string(),
        "jo0001.github.io".to_string(),
        "logging.apache.org".to_string(),
        "login.live.com".to_string(),
        "lwjgl.org".to_string(),
        "minecraft.net".to_string(),
        "minecraft.org".to_string(),
        "minotar.net".to_string(),
        "mojang.com".to_string(),
        "netty.io".to_string(),
        "optifine.net".to_string(),
        "paulscode/sound/".to_string(),
        "s.optifine.net".to_string(),
        "sessionserver.mojang.com".to_string(),
        "shader-tutorial.dev".to_string(),
        "snoop.minecraft.net".to_string(),
        "tools.ietf.org".to_string(),
        "viaversion.com".to_string(),
        "www.openssl.org".to_string(),
        "www.rfc-editor.org".to_string(),
        "www.slf4j.org".to_string(),
        "www.w3.org".to_string(),
        "yaml.org".to_string(),
        "openssl.org".to_string(),
        "yggdrasil-auth-session-staging.mojang.zone".to_string(),
        "slf4j.org".to_string(),
    ];

    /// Known "good" / unreachable / reserved IPs and ranges
    pub static ref GOOD_IPS: HashSet<&'static str> = {
        let mut s = HashSet::new();
        // Unspecified / non-routable single addresses
        s.insert("0.0.0.0");
        s.insert("::");

        // Loopback
        s.insert("127.0.0.1");
        s.insert("::1");

        // Broadcast
        s.insert("255.255.255.255");

        // Link-local (often unreachable from other networks)
        s.insert("169.254.0.0/16");

        // Documentation / TEST-NET ranges (RFC 5737) - used in examples/tests
        s.insert("192.0.2.0/24");
        s.insert("198.51.100.0/24");
        s.insert("203.0.113.0/24");

        // Private address ranges (commonly non-public)
        s.insert("10.0.0.0/8");
        s.insert("172.16.0.0/12");
        s.insert("192.168.0.0/16");

        // Minecraft UDP multicast address
        s.insert("224.0.2.60");

        // DNS resolvers
        s.insert("8.8.8.8");
        s.insert("8.8.4.4");
        s.insert("1.1.1.1");
        s.insert("9.9.9.9");

        s
    };

    pub static ref GOOD_IP_ADDRS: HashSet<IpAddr> = {
        let mut out = HashSet::new();
        for s in GOOD_IPS.iter() {
            if !s.contains('/') {
                if let Ok(a) = s.parse::<IpAddr>() {
                    out.insert(a);
                }
            }
        }
        out
    };

    pub static ref GOOD_IP_NETWORKS: Vec<IpNet> = {
        let mut out = Vec::new();
        for s in GOOD_IPS.iter() {
            if s.contains('/') {
                if let Ok(n) = s.parse::<IpNet>() {
                    out.push(n);
                }
            }
        }
        out
    };
}

pub fn is_known_good_ip(ip: &str) -> bool {
    if let Ok(addr) = ip.parse::<IpAddr>() {
        if GOOD_IP_ADDRS.contains(&addr) {
            return true;
        }

        for net in GOOD_IP_NETWORKS.iter() {
            if net.contains(&addr) {
                return true;
            }
        }
    }
    false
}
