with open("crates/guardian-cli/src/ca.rs", "r") as f:
    content = f.read()
content = content.replace("    }\n    }\n\n    use std::sync::Mutex;", "    }\n\n    use std::sync::Mutex;")
with open("crates/guardian-cli/src/ca.rs", "w") as f:
    f.write(content)
