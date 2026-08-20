use std::fs;
use std::path::PathBuf;
use serde_json::Value;

pub struct ConfigPatcher {
    cursor_settings_path: Option<PathBuf>,
    original_cursor_content: Option<String>,
    vscode_settings_path: Option<PathBuf>,
    original_vscode_content: Option<String>,
}

impl Default for ConfigPatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigPatcher {
    pub fn new() -> Self {
        Self {
            cursor_settings_path: None,
            original_cursor_content: None,
            vscode_settings_path: None,
            original_vscode_content: None,
        }
    }

    pub fn get_cursor_path() -> Option<PathBuf> {
        let home = std::env::var("HOME").ok()?;
        #[cfg(target_os = "macos")]
        let p = PathBuf::from(&home).join("Library/Application Support/Cursor/User/settings.json");
        #[cfg(target_os = "linux")]
        let p = PathBuf::from(&home).join(".config/Cursor/User/settings.json");
        #[cfg(target_os = "windows")]
        let p = PathBuf::from(std::env::var("APPDATA").unwrap_or_default()).join("Cursor/User/settings.json");
        Some(p)
    }

    pub fn get_vscode_path() -> Option<PathBuf> {
        let home = std::env::var("HOME").ok()?;
        #[cfg(target_os = "macos")]
        let p = PathBuf::from(&home).join("Library/Application Support/Code/User/settings.json");
        #[cfg(target_os = "linux")]
        let p = PathBuf::from(&home).join(".config/Code/User/settings.json");
        #[cfg(target_os = "windows")]
        let p = PathBuf::from(std::env::var("APPDATA").unwrap_or_default()).join("Code/User/settings.json");
        Some(p)
    }

    pub fn patch(&mut self, port: u16) -> Result<(), String> {
        let proxy_url = format!("http://127.0.0.1:{}", port);

        if let Some(path) = Self::get_cursor_path() {
            if path.exists() {
                let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
                self.original_cursor_content = Some(content.clone());
                self.cursor_settings_path = Some(path.clone());

                let new_content = Self::patch_json_string(&content, &proxy_url);
                fs::write(&path, new_content).map_err(|e| e.to_string())?;
                tracing::info!("Patched Cursor settings at {:?}", path);
            } else {
                tracing::debug!("Cursor settings not found at {:?}", path);
            }
        }

        if let Some(path) = Self::get_vscode_path() {
            if path.exists() {
                let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
                self.original_vscode_content = Some(content.clone());
                self.vscode_settings_path = Some(path.clone());

                let new_content = Self::patch_json_string(&content, &proxy_url);
                fs::write(&path, new_content).map_err(|e| e.to_string())?;
                tracing::info!("Patched VSCode settings at {:?}", path);
            } else {
                tracing::debug!("VSCode settings not found at {:?}", path);
            }
        }
        
        println!("\n=======================================================");
        println!("🛡️  LLM Firewall is running on port {}", port);
        println!("=======================================================");
        println!("For Claude Code, please run the following in your terminal:");
        println!("  export HTTP_PROXY=http://127.0.0.1:{}", port);
        println!("  export HTTPS_PROXY=http://127.0.0.1:{}", port);
        println!("  export NODE_TLS_REJECT_UNAUTHORIZED=0");
        println!("=======================================================\n");
        
        Self::detect_ide_processes();
        
        Ok(())
    }

    pub fn restore(&self) -> Result<(), String> {
        if let (Some(path), Some(content)) = (&self.cursor_settings_path, &self.original_cursor_content) {
            if path.exists() {
                fs::write(path, content).map_err(|e| e.to_string())?;
                tracing::info!("Restored Cursor settings at {:?}", path);
            }
        }
        if let (Some(path), Some(content)) = (&self.vscode_settings_path, &self.original_vscode_content) {
            if path.exists() {
                fs::write(path, content).map_err(|e| e.to_string())?;
                tracing::info!("Restored VSCode settings at {:?}", path);
            }
        }
        Ok(())
    }

    pub fn patch_json_string(content: &str, proxy_url: &str) -> String {
        let lines: Vec<&str> = content.lines().collect();
        let mut new_lines = Vec::new();
        
        // Remove existing proxy settings
        for line in lines {
            if !line.contains("\"http.proxy\"") && !line.contains("\"http.proxyStrictSSL\"") {
                new_lines.push(line.to_string());
            } else {
                // If the previous line had a comma and this was the last item, we might leave a trailing comma.
                // It's a bit complex to handle perfectly with just lines, but we'll try to ensure valid JSON.
            }
        }
        
        let rebuilt = new_lines.join("\n");
        let rb_trimmed = rebuilt.trim_end();
        
        if let Some(stripped) = rb_trimmed.strip_suffix('}') {
            let mut base = stripped.trim_end().to_string();
            if !base.is_empty() && !base.ends_with(',') && !base.ends_with('{') {
                base.push(',');
            }
            base.push_str("\n  \"http.proxy\": \"");
            base.push_str(proxy_url);
            base.push_str("\",\n  \"http.proxyStrictSSL\": false\n}");
            return base;
        }
        
        if let Ok(mut v) = serde_json::from_str::<Value>(content) {
            if let Some(obj) = v.as_object_mut() {
                obj.insert("http.proxy".to_string(), Value::String(proxy_url.to_string()));
                obj.insert("http.proxyStrictSSL".to_string(), Value::Bool(false));
                return serde_json::to_string_pretty(&v).unwrap_or(content.to_string());
            }
        }
        
        content.to_string()
    }

    pub fn detect_ide_processes() {
        #[cfg(unix)]
        {
            if let Ok(output) = std::process::Command::new("pgrep").arg("-i").arg("cursor").output() {
                if !output.stdout.is_empty() {
                    println!("⚠️  Detected running Cursor instance. Please restart Cursor to pick up the new proxy settings.");
                }
            }
            if let Ok(output) = std::process::Command::new("pgrep").arg("-i").arg("code").output() {
                if !output.stdout.is_empty() {
                    println!("⚠️  Detected running VSCode instance. Please restart VSCode to pick up the new proxy settings.");
                }
            }
        }
        #[cfg(windows)]
        {
            if let Ok(output) = std::process::Command::new("tasklist").output() {
                let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
                if stdout.contains("cursor.exe") {
                    println!("⚠️  Detected running Cursor instance. Please restart Cursor to pick up the new proxy settings.");
                }
                if stdout.contains("code.exe") {
                    println!("⚠️  Detected running VSCode instance. Please restart VSCode to pick up the new proxy settings.");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patch_json_string_empty() {
        let content = "{}";
        let proxy_url = "http://127.0.0.1:3000";
        let patched = ConfigPatcher::patch_json_string(content, proxy_url);
        assert!(patched.contains("\"http.proxy\": \"http://127.0.0.1:3000\""));
        assert!(patched.contains("\"http.proxyStrictSSL\": false"));
    }

    #[test]
    fn test_patch_json_string_preserves_formatting() {
        let content = "{\n  // A comment\n  \"some.setting\": true\n}";
        let proxy_url = "http://127.0.0.1:3000";
        let patched = ConfigPatcher::patch_json_string(content, proxy_url);
        assert!(patched.contains("// A comment"));
        assert!(patched.contains("\"some.setting\": true,"));
        assert!(patched.contains("\"http.proxy\": \"http://127.0.0.1:3000\""));
    }

    #[test]
    fn test_patch_json_string_replaces_existing() {
        let content = "{\n  \"http.proxy\": \"http://old:8080\",\n  \"http.proxyStrictSSL\": true\n}";
        let proxy_url = "http://127.0.0.1:3000";
        let patched = ConfigPatcher::patch_json_string(content, proxy_url);
        assert!(!patched.contains("old:8080"));
        assert!(patched.contains("\"http.proxy\": \"http://127.0.0.1:3000\""));
    }
}
