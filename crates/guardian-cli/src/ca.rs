use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct LocalCA {
    pub cert_path: PathBuf,
}

impl LocalCA {
    pub fn new(cert_dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        fs::create_dir_all(cert_dir)?;
        let cert_path = cert_dir.join("llm-firewall-ca.pem");
        let key_path = cert_dir.join("llm-firewall-ca.key");

        if !cert_path.exists() || !key_path.exists() {
            let mut params = CertificateParams::default();
            let mut dn = DistinguishedName::new();
            dn.push(rcgen::DnType::CommonName, "LLM Firewall Local CA");
            params.distinguished_name = dn;
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));

            let key_pair = KeyPair::generate()?;
            let cert = params.self_signed(&key_pair)?;

            let mut cert_file = fs::File::create(&cert_path)?;
            cert_file.write_all(cert.pem().as_bytes())?;

            let mut key_file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&key_path)?;
            key_file.write_all(key_pair.serialize_pem().as_bytes())?;
        }

        Ok(Self { cert_path })
    }

    pub fn trust_with_runner<R: CommandRunner>(
        &self,
        runner: &R,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cert_path_str = self
            .cert_path
            .to_str()
            .ok_or("Certificate path contains non-UTF8 characters")?;
        if cfg!(target_os = "macos") {
            runner.run(
                "security",
                &[
                    "add-trusted-cert",
                    "-d",
                    "-r",
                    "trustRoot",
                    "-k",
                    "/Library/Keychains/System.keychain",
                    cert_path_str,
                ],
            )?;
        } else {
            return Err("OS not supported for local CA trust".into());
        }
        Ok(())
    }

    pub fn untrust_with_runner<R: CommandRunner>(
        &self,
        runner: &R,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cert_path_str = self
            .cert_path
            .to_str()
            .ok_or("Certificate path contains non-UTF8 characters")?;
        if cfg!(target_os = "macos") {
            runner.run("security", &["remove-trusted-cert", "-d", cert_path_str])?;
        } else {
            return Err("OS not supported for local CA untrust".into());
        }
        Ok(())
    }

    pub fn trust(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.trust_with_runner(&RealCommandRunner)
    }

    pub fn untrust(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.untrust_with_runner(&RealCommandRunner)
    }
}

pub trait CommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<(), Box<dyn std::error::Error>>;
}

pub struct RealCommandRunner;

impl CommandRunner for RealCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
        let output = Command::new(program).args(args).output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("Command {} failed: {}", program, stderr).into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_local_ca_generation() {
        let dir = tempdir().unwrap();
        let ca = LocalCA::new(dir.path()).expect("Failed to create CA");

        assert!(ca.cert_path.exists());
        let key_path = dir.path().join("llm-firewall-ca.key");
        assert!(key_path.exists());

        // Verify the certificate
        let cert_content = fs::read(&ca.cert_path).unwrap();
        let (_, pem) = x509_parser::pem::parse_x509_pem(&cert_content).unwrap();
        let cert = pem.parse_x509().unwrap();

        assert_eq!(cert.subject().to_string(), "CN=LLM Firewall Local CA");
        assert!(cert.is_ca());
    }

    #[test]
    fn test_local_ca_generation_idempotent() {
        let dir = tempdir().unwrap();
        let ca1 = LocalCA::new(dir.path()).unwrap();
        let meta1 = fs::metadata(&ca1.cert_path).unwrap();

        let ca2 = LocalCA::new(dir.path()).unwrap();
        let meta2 = fs::metadata(&ca2.cert_path).unwrap();

        assert_eq!(
            meta1.modified().unwrap(),
            meta2.modified().unwrap(),
            "Certificate should not be regenerated if it exists"
        );
    }

    use std::sync::Mutex;

    struct MockRunner {
        commands: Mutex<Vec<(String, Vec<String>)>>,
    }

    impl MockRunner {
        fn new() -> Self {
            Self {
                commands: Mutex::new(Vec::new()),
            }
        }
    }

    impl CommandRunner for MockRunner {
        fn run(&self, program: &str, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
            let mut guard = self.commands.lock().unwrap();
            guard.push((
                program.to_string(),
                args.iter().map(|s| s.to_string()).collect(),
            ));
            Ok(())
        }
    }

    #[test]
    fn test_trust_untrust_commands() {
        let dir = tempdir().unwrap();
        let ca = LocalCA::new(dir.path()).unwrap();
        let runner = MockRunner::new();

        let _ = ca.trust_with_runner(&runner);
        let _ = ca.untrust_with_runner(&runner);

        let cmds = runner.commands.lock().unwrap();

        if cfg!(target_os = "macos") {
            assert_eq!(cmds.len(), 2);
            assert_eq!(cmds[0].0, "security");
            assert_eq!(cmds[0].1[0], "add-trusted-cert");
            assert_eq!(cmds[0].1[4], "-k");
            assert_eq!(cmds[0].1.last().unwrap(), ca.cert_path.to_str().unwrap());

            assert_eq!(cmds[1].0, "security");
            assert_eq!(cmds[1].1[0], "remove-trusted-cert");
            assert_eq!(cmds[1].1.last().unwrap(), ca.cert_path.to_str().unwrap());
        }
    }
}
