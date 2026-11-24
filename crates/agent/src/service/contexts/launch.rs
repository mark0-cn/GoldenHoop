//! Bounded, image-owned kernelspec discovery. Never consult a workload HOME,
//! workspace, JUPYTER_PATH, inherited environment or a caller-selected URL.
use goldenhoop_jupyter::peer::IpcNaming;
use goldenhoop_protocol::CodeLanguage;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io::{self, Read},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

const MAX_SPEC_BYTES: u64 = 64 * 1024;
const ROOTS: [&str; 2] = [
    "/usr/local/share/jupyter/kernels",
    "/usr/share/jupyter/kernels",
];

pub(super) struct Launch {
    pub program: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub naming: IpcNaming,
}
impl Launch {
    pub fn load(language: CodeLanguage) -> io::Result<Self> {
        // Preserve the established isolated Python launcher. Other languages
        // never take this branch when their own dependency/spec is missing.
        if language == CodeLanguage::Python {
            return Ok(Self {
                program: "python3".into(),
                args: ["-I", "-m", "ipykernel_launcher", "-f", "{connection_file}"]
                    .map(String::from)
                    .into(),
                env: BTreeMap::new(),
                naming: IpcNaming::Dash,
            });
        }
        for root in ROOTS {
            if let Some(plan) = Self::at(Path::new(root), language)? {
                return Ok(plan);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("image has no system kernelspec for {}", language.as_str()),
        ))
    }

    fn at(root: &Path, language: CodeLanguage) -> io::Result<Option<Self>> {
        let name = match language {
            CodeLanguage::Python => "python3",
            CodeLanguage::Java => "java",
            CodeLanguage::Go => "gophernotes",
            CodeLanguage::TypeScript => "tslab",
            CodeLanguage::Bash => "bash",
            CodeLanguage::JavaScript => "jslab",
        };
        let path = root.join(name).join("kernel.json");
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_SPEC_BYTES {
            return Err(invalid("kernelspec must be a bounded regular file"));
        }
        let resolved_root = root.canonicalize()?;
        if resolved_root != root {
            return Err(invalid(
                "system kernel root must not redirect to another tree",
            ));
        }
        let root = resolved_root;
        let directory = path
            .parent()
            .expect("system kernelspec parent")
            .canonicalize()?;
        if directory == root || !directory.starts_with(&root) {
            return Err(invalid(
                "kernelspec directory escapes the system kernel root",
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAX_SPEC_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() > MAX_SPEC_BYTES as usize {
            return Err(invalid("kernelspec exceeds size limit"));
        }
        Self::parse(&bytes, &directory, language).map(Some)
    }

    fn parse(bytes: &[u8], directory: &Path, language: CodeLanguage) -> io::Result<Self> {
        let spec: Value =
            serde_json::from_slice(bytes).map_err(|_| invalid("invalid kernelspec JSON"))?;
        if !spec["language"]
            .as_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(language.as_str()))
        {
            return Err(invalid(
                "kernelspec language does not match the requested language",
            ));
        }
        let argv = spec["argv"]
            .as_array()
            .filter(|args| !args.is_empty() && args.len() <= 64)
            .ok_or_else(|| invalid("kernelspec argv must have 1-64 literal arguments"))?;
        let mut args = Vec::new();
        let mut connections = 0;
        for arg in argv {
            let arg = arg
                .as_str()
                .filter(|value| value.len() <= 4096 && !value.contains('\0'))
                .ok_or_else(|| invalid("invalid kernelspec argument"))?;
            connections += arg.matches("{connection_file}").count();
            args.push(arg.replace("{resource_dir}", &directory.to_string_lossy()));
        }
        let program = args.remove(0);
        if program.is_empty()
            || program.contains('{')
            || (program.contains('/') && !Path::new(&program).is_absolute())
            || connections != 1
        {
            return Err(invalid(
                "invalid kernelspec executable or connection-file placeholder",
            ));
        }
        let mut env = BTreeMap::new();
        if let Some(value) = spec.get("env") {
            let values = value
                .as_object()
                .filter(|values| values.len() <= 32)
                .ok_or_else(|| invalid("kernelspec env must be a bounded string map"))?;
            for (key, value) in values {
                if key.is_empty()
                    || key.len() > 128
                    || !key.bytes().enumerate().all(|(i, b)| {
                        b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit())
                    })
                {
                    return Err(invalid("invalid kernelspec environment key"));
                }
                let value = value
                    .as_str()
                    .filter(|value| value.len() <= 4096 && !value.contains('\0'))
                    .ok_or_else(|| invalid("invalid kernelspec environment value"))?;
                // Values are literal. In particular, ${HOST_VARIABLE} is never
                // expanded, and the launcher enforces its private HOME/dirs.
                env.insert(key.clone(), value.to_owned());
            }
        }
        let naming = match spec.pointer("/metadata/goldenhoop/ipc_path_style") {
            None | Some(Value::Null) => IpcNaming::Dash,
            Some(Value::String(style)) if style == "dash" => IpcNaming::Dash,
            Some(Value::String(style)) if style == "colon" => IpcNaming::Colon,
            _ => return Err(invalid("unsupported IPC socket naming convention")),
        };
        Ok(Self {
            program,
            args,
            env,
            naming,
        })
    }
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::symlink;

    #[test]
    fn kernelspec_is_literal_bounded_language_specific_and_never_uses_host_environment() {
        let directory = Path::new("/usr/share/jupyter/kernels/tslab");
        let mut spec = json!({"language":"typescript","argv":["node","{resource_dir}/kernel.js","--connection={connection_file}","$(touch unwanted)"],
            "env":{"LITERAL":"${HOME}"},"metadata":{"goldenhoop":{"ipc_path_style":"colon"}}});
        let parse = |value: &Value| {
            Launch::parse(
                &serde_json::to_vec(value).unwrap(),
                directory,
                CodeLanguage::TypeScript,
            )
        };
        let plan = parse(&spec).unwrap();
        assert_eq!(plan.program, "node");
        assert_eq!(plan.args[0], "/usr/share/jupyter/kernels/tslab/kernel.js");
        assert_eq!(plan.args[2], "$(touch unwanted)");
        assert_eq!(plan.env["LITERAL"], "${HOME}");
        assert_eq!(
            plan.naming.path(Path::new("/tmp/private/kernel"), 1),
            Path::new("/tmp/private/kernel:1")
        );
        spec["language"] = json!("javascript");
        assert!(parse(&spec).is_err());
        spec["language"] = json!("typescript");
        spec["argv"][2] = json!("missing-placeholder");
        assert!(parse(&spec).is_err());
        spec["argv"][2] = json!("{connection_file}{connection_file}");
        assert!(parse(&spec).is_err());
        spec["argv"][2] = json!("{connection_file}");
        spec["metadata"]["goldenhoop"]["ipc_path_style"] = json!("tcp");
        assert!(parse(&spec).is_err());
        spec["metadata"]["goldenhoop"]["ipc_path_style"] = json!("dash");
        spec["argv"] = json!(["node", "{connection_file}", "x".repeat(4097)]);
        assert!(parse(&spec).is_err());
        spec["argv"] = json!(["node", "{connection_file}"]);
        spec["env"]["BAD=KEY"] = json!("value");
        assert!(parse(&spec).is_err());
    }

    #[test]
    fn discovery_refuses_symlink_escapes_nonregular_and_oversized_specs() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("system");
        let directory = root.join("bash");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("kernel.json");
        assert!(Launch::at(&root, CodeLanguage::Bash).unwrap().is_none());
        let spec = br#"{"language":"bash","argv":["bash-kernel","{connection_file}"]}"#;
        std::fs::write(&path, spec).unwrap();
        assert!(Launch::at(&root, CodeLanguage::Bash).unwrap().is_some());
        std::fs::write(&path, vec![b' '; MAX_SPEC_BYTES as usize + 1]).unwrap();
        assert!(Launch::at(&root, CodeLanguage::Bash).is_err());
        std::fs::remove_file(&path).unwrap();
        let outside = temp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("kernel.json"), spec).unwrap();
        symlink(outside.join("kernel.json"), &path).unwrap();
        assert!(Launch::at(&root, CodeLanguage::Bash).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&directory).unwrap();
        symlink(&outside, &directory).unwrap();
        assert!(Launch::at(&root, CodeLanguage::Bash).is_err());
        std::fs::remove_file(&directory).unwrap();
        std::fs::create_dir(&directory).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(Launch::at(&root, CodeLanguage::Bash).is_err());
    }
}
