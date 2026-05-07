use crate::types::{ClassDetails, FindingType};
use crate::utils::truncate_string;
use std::collections::HashSet;

pub const PROCESS_EXECUTION_MARKERS: &[&str] = &[
    "java/lang/Runtime",
    "getRuntime",
    "exec",
    "ProcessBuilder",
    "java/lang/ProcessBuilder",
];

pub const REFLECTION_MARKERS: &[&str] = &[
    "java/lang/reflect/Method",
    "java/lang/reflect/Field",
    "java/lang/reflect/Constructor",
    "setAccessible",
    "invoke",
];

pub const DYNAMIC_LOADING_MARKERS: &[&str] = &[
    "defineClass",
    "URLClassLoader",
    "MethodHandles$Lookup",
    "Lookup.defineClass",
];

pub const SCRIPT_ENGINE_MARKERS: &[&str] = &[
    "javax/script/ScriptEngineManager",
    "javax/script/ScriptEngine",
];

pub const JAVA_AGENT_MARKERS: &[&str] = &[
    "java/lang/instrument/Instrumentation",
    "Premain-Class",
    "Agent-Class",
    "Launcher-Agent-Class",
];

pub const ATTACH_API_MARKERS: &[&str] = &[
    "com/sun/tools/attach/VirtualMachine",
    "sun/tools/attach/HotSpotVirtualMachine",
];

pub const NATIVE_BRIDGE_MARKERS: &[&str] = &[
    "com/sun/jna/Native",
    "com/sun/jna/Library",
    "sun/misc/Unsafe",
];

pub struct ApiAnalyzer;

impl ApiAnalyzer {
    pub fn analyze(details: &ClassDetails, findings: &mut Vec<(FindingType, String)>) {
        let string_set: HashSet<&str> = details.strings.iter().map(String::as_str).collect();

        if PROCESS_EXECUTION_MARKERS
            .iter()
            .any(|m| string_set.contains(m))
        {
            let cmd = Self::guess_command(&details.strings);
            findings.push((
                FindingType::SuspiciousApi,
                format!(
                    "Process execution API usage{}",
                    if cmd.is_empty() {
                        "".to_string()
                    } else {
                        format!(": Likely running \"{}\"", cmd)
                    }
                ),
            ));
        }

        if REFLECTION_MARKERS.iter().any(|m| string_set.contains(m)) {
            let target = Self::guess_reflected_target(details);
            findings.push((
                FindingType::SuspiciousApi,
                format!(
                    "Reflection-based access{}",
                    if target.is_empty() {
                        "".to_string()
                    } else {
                        format!(": Likely targeting \"{}\"", target)
                    }
                ),
            ));
        }

        Self::check_marker(
            &string_set,
            DYNAMIC_LOADING_MARKERS,
            "Dynamic class loading or definition",
            findings,
        );
        Self::check_marker(
            &string_set,
            SCRIPT_ENGINE_MARKERS,
            "Script engine execution",
            findings,
        );
        Self::check_marker(
            &string_set,
            JAVA_AGENT_MARKERS,
            "Java agent instrumentation",
            findings,
        );
        Self::check_marker(
            &string_set,
            ATTACH_API_MARKERS,
            "JVM attach API usage",
            findings,
        );
        Self::check_marker(
            &string_set,
            NATIVE_BRIDGE_MARKERS,
            "Native bridge or Unsafe API usage",
            findings,
        );
    }

    fn check_marker(
        string_set: &HashSet<&str>,
        markers: &[&str],
        message: &str,
        findings: &mut Vec<(FindingType, String)>,
    ) {
        if markers.iter().any(|marker| string_set.contains(marker)) {
            findings.push((FindingType::SuspiciousApi, message.to_string()));
        }
    }

    fn guess_command(strings: &[String]) -> String {
        for s in strings {
            let lower = s.to_lowercase();
            if lower.contains("cmd.exe")
                || lower.contains("/bin/sh")
                || lower.contains("/bin/bash")
                || lower.contains("powershell")
                || lower.contains("curl ")
                || lower.contains("wget ")
            {
                return truncate_string(s, 60);
            }
        }
        "".to_string()
    }

    fn guess_reflected_target(details: &ClassDetails) -> String {
        for method in &details.methods {
            if method.name == "getDeclaredMethod" || method.name == "getDeclaredField" {
                return format!("Method/Field: {}", method.name);
            }
        }
        for field in &details.fields {
            if field.name.len() > 5 && !field.name.contains('/') {
                return field.name.clone();
            }
        }
        "".to_string()
    }
}
