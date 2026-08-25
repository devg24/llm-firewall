pub use crate::config::{
    parse_guardian_toml, parse_guardian_toml_str, AllowlistConfig, CustomRegexRule, GuardianConfig,
    RegexConfig, ThresholdOverrides,
};
pub use crate::discovery::detect_domain_from_manifests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::DomainProfile;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_detect_crypto_from_cargo_toml() {
        let dir = tempdir().unwrap();
        let cargo_toml = r#"
        [dependencies]
        ethers = "2.0"
        "#;
        fs::write(dir.path().join("Cargo.toml"), cargo_toml).unwrap();
        assert_eq!(
            detect_domain_from_manifests(dir.path()),
            DomainProfile::CryptoFintech
        );
    }

    #[test]
    fn test_detect_healthcare_from_package_json() {
        let dir = tempdir().unwrap();
        let pkg_json = r#"
        {
            "dependencies": {
                "fhir": "1.0.0"
            }
        }
        "#;
        fs::write(dir.path().join("package.json"), pkg_json).unwrap();
        assert_eq!(
            detect_domain_from_manifests(dir.path()),
            DomainProfile::Healthcare
        );
    }

    #[test]
    fn test_detect_crypto_from_go_mod() {
        let dir = tempdir().unwrap();
        let go_mod = r#"
        module example.com/mycrypto

        go 1.22

        require (
            github.com/ethereum/go-ethereum v1.13.5
        )
        "#;
        fs::write(dir.path().join("go.mod"), go_mod).unwrap();
        assert_eq!(
            detect_domain_from_manifests(dir.path()),
            DomainProfile::CryptoFintech
        );
    }

    #[test]
    fn test_detect_python_requirements_and_pyproject() {
        let dir = tempdir().unwrap();
        let reqs = "web3.py>=6.0.0\nrequests==2.31.0\n";
        fs::write(dir.path().join("requirements.txt"), reqs).unwrap();
        assert_eq!(
            detect_domain_from_manifests(dir.path()),
            DomainProfile::CryptoFintech
        );

        let dir2 = tempdir().unwrap();
        let pyproj = r#"
        [project]
        dependencies = [
            "medplum>=0.1.0",
        ]
        "#;
        fs::write(dir2.path().join("pyproject.toml"), pyproj).unwrap();
        assert_eq!(
            detect_domain_from_manifests(dir2.path()),
            DomainProfile::Healthcare
        );
    }

    #[test]
    fn test_malformed_guardian_toml_fallback() {
        let dir = tempdir().unwrap();
        let bad_toml = r#"
        [regex
        rules = [
        "#;
        fs::write(dir.path().join(".guardian.toml"), bad_toml).unwrap();
        // Should fallback silently and return standard if no domain is detected
        assert_eq!(
            detect_domain_from_manifests(dir.path()),
            DomainProfile::Standard
        );
        assert!(parse_guardian_toml(&dir.path().join(".guardian.toml")).is_none());
    }

    #[test]
    fn test_guardian_toml_custom_rules_and_thresholds() {
        let toml_str = r#"
        domain = "healthcare"

        [thresholds]
        entropy = 4.7
        ner = 0.85

        [[rules]]
        id = "company_secret"
        pattern = "SECRET_[A-Z0-9]{8}"
        pii_type = "CUSTOM"

        [allowlist]
        terms = ["ALLOWED_TOKEN", "PUBLIC_VAR"]
        patterns = ["DEBUG_.*"]
        "#;

        let cfg = parse_guardian_toml_str(toml_str).expect("Should parse valid toml");
        assert_eq!(cfg.domain.as_deref(), Some("healthcare"));
        let th = cfg.thresholds.unwrap();
        assert_eq!(th.entropy, Some(4.7));
        assert_eq!(th.ner, Some(0.85));

        let rules = cfg.rules.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "company_secret");

        let allowlist = cfg.allowlist.unwrap();
        assert_eq!(
            allowlist.terms.unwrap(),
            vec!["ALLOWED_TOKEN", "PUBLIC_VAR"]
        );
        assert_eq!(allowlist.patterns.unwrap(), vec!["DEBUG_.*"]);
    }

    #[test]
    fn test_guardian_toml_invalid_regex_rejected() {
        let bad_regex = r#"
        [[rules]]
        id = "bad"
        pattern = "(unclosed"
        "#;
        let config = parse_guardian_toml_str(bad_regex).expect("Should parse");
        assert!(config.rules.unwrap().is_empty());

        let bad_allowlist_regex = r#"
        [allowlist]
        patterns = ["[a-z"]
        "#;
        let config2 = parse_guardian_toml_str(bad_allowlist_regex).expect("Should parse");
        assert!(config2.allowlist.unwrap().patterns.unwrap().is_empty());
    }

    #[test]
    fn test_monorepo_discovery() {
        let dir = tempdir().unwrap();
        let sub = dir.path().join("crates").join("subcrate");
        fs::create_dir_all(&sub).unwrap();
        let cargo_toml = r#"
        [dependencies]
        solana = "1.0"
        "#;
        fs::write(sub.join("Cargo.toml"), cargo_toml).unwrap();

        // Ignored node_modules should not crash
        let ignored_dir = dir.path().join("node_modules").join("fake-crypto");
        fs::create_dir_all(&ignored_dir).unwrap();
        fs::write(
            ignored_dir.join("package.json"),
            r#"{"dependencies":{"ethers":"1.0"}}"#,
        )
        .unwrap();

        assert_eq!(
            detect_domain_from_manifests(dir.path()),
            DomainProfile::CryptoFintech
        );
    }
}
