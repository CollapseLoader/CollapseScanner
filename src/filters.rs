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
    pub static ref MALICIOUS_PATTERN_REGEX: Regex = Regex::new(r"(?i)\b(powershell|cmd\.exe|Runtime\.getRuntime\(\)\.exec)\b").unwrap();

    /// Known "good" links / domains
    pub static ref GOOD_LINKS: HashSet<String> = [
        "account.mojang.com",
        "aka.ms",
        "apache.org",
        "api.mojang.com",
        "api.spiget.org",
        "authserver.mojang.com",
        "bugs.mojang.com",
        "cabaletta/baritone",
        "ci.viaversion.com",
        "com/viaversion/",
        "docs.advntr.dev",
        "dominos.com",
        "dump.viaversion.com",
        "eclipse.org",
        "java.sun.org",
        "jo0001.github.io",
        "logging.apache.org",
        "login.live.com",
        "lwjgl.org",
        "minecraft.net",
        "minecraft.org",
        "minotar.net",
        "mojang.com",
        "netty.io",
        "optifine.net",
        "paulscode/sound/",
        "s.optifine.net",
        "sessionserver.mojang.com",
        "shader-tutorial.dev",
        "snoop.minecraft.net",
        "tools.ietf.org",
        "viaversion.com",
        "www.openssl.org",
        "www.rfc-editor.org",
        "www.slf4j.org",
        "www.w3.org",
        "yaml.org",
        "openssl.org",
        "yggdrasil-auth-session-staging.mojang.zone",
        "slf4j.org",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();

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

pub fn is_public_routable_ip(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(addr) => {
            if is_known_good_ip(ip) {
                return false;
            }

            match addr {
                IpAddr::V4(v4) => {
                    !(v4.is_private()
                        || v4.is_loopback()
                        || v4.is_link_local()
                        || v4.is_broadcast()
                        || v4.is_documentation()
                        || v4.is_multicast()
                        || v4.is_unspecified())
                }
                IpAddr::V6(v6) => {
                    let segments = v6.segments();
                    let is_site_local = (segments[0] & 0xffc0) == 0xfec0;
                    let is_documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;

                    !(v6.is_loopback()
                        || v6.is_unspecified()
                        || v6.is_unique_local()
                        || v6.is_unicast_link_local()
                        || is_site_local
                        || is_documentation
                        || v6.is_multicast())
                }
            }
        }
        Err(_) => false,
    }
}
