pub mod apk;
pub mod dex;
pub mod minidex;
pub mod service;

mod dex_format;

use anyhow::{Result, bail};

/// Convert a Java-style class name into a Dalvik descriptor.
pub fn format_class_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        bail!("class name cannot be empty");
    }
    if name.starts_with('L') && name.ends_with(';') && name.contains('/') {
        return Ok(name.to_owned());
    }

    let mut result = name.replace('.', "/");
    if !result.starts_with('L') {
        result.insert(0, 'L');
    }
    if !result.ends_with(';') {
        result.push(';');
    }
    Ok(result)
}

pub fn descriptor_to_java(descriptor: &str) -> String {
    descriptor
        .strip_prefix('L')
        .and_then(|s| s.strip_suffix(';'))
        .unwrap_or(descriptor)
        .replace('/', ".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_class_names() {
        assert_eq!(
            format_class_name("com.example.Main").unwrap(),
            "Lcom/example/Main;"
        );
        assert_eq!(
            format_class_name("Lcom/example/Main;").unwrap(),
            "Lcom/example/Main;"
        );
    }
}
