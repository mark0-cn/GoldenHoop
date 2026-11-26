use goldenhoop_credentials::*;
use uuid::Uuid;

#[test]
fn ciphertext_authenticates_all_identity_fields_and_uses_fresh_nonces() {
    let key = VaultKey::from_bytes([17; 32]);
    let installation = Uuid::new_v4();
    let sandbox = Uuid::new_v4();
    let binding = Uuid::new_v4();
    let one = key
        .seal(
            installation,
            sandbox,
            binding,
            1,
            b"provider-private-test-value",
        )
        .unwrap();
    let two = key
        .seal(
            installation,
            sandbox,
            binding,
            1,
            b"provider-private-test-value",
        )
        .unwrap();
    assert_ne!(one.nonce, two.nonce);
    assert_ne!(one.ciphertext, two.ciphertext);
    assert_eq!(
        key.unseal(installation, sandbox, binding, 1, &one)
            .unwrap()
            .as_slice(),
        b"provider-private-test-value"
    );
    for (i, s, b, r) in [
        (Uuid::new_v4(), sandbox, binding, 1),
        (installation, Uuid::new_v4(), binding, 1),
        (installation, sandbox, Uuid::new_v4(), 1),
        (installation, sandbox, binding, 2),
    ] {
        assert!(key.unseal(i, s, b, r, &one).is_err());
    }
    let wrong = VaultKey::from_bytes([18; 32]);
    assert!(
        wrong
            .unseal(installation, sandbox, binding, 1, &one)
            .is_err()
    );
    let mut damaged = one;
    damaged.ciphertext[0] ^= 1;
    assert!(
        key.unseal(installation, sandbox, binding, 1, &damaged)
            .is_err()
    );
    assert_ne!(
        key.fingerprint(b"a", b"weak-secret").unwrap(),
        key.fingerprint(b"b", b"weak-secret").unwrap()
    );
    assert_ne!(
        key.fingerprint(b"a", b"weak-secret").unwrap(),
        wrong.fingerprint(b"a", b"weak-secret").unwrap()
    );
}

#[test]
fn explicit_master_key_provisioning_never_replaces_existing_or_invalid_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("master.key");
    VaultKey::create(&path).unwrap();
    let before = std::fs::read(&path).unwrap();
    VaultKey::open(&path).unwrap();
    assert!(VaultKey::create(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let invalid = dir.path().join("invalid.key");
    std::fs::write(&invalid, [0; 31]).unwrap();
    assert!(VaultKey::open(&invalid).is_err());
    let root = dir.path().to_owned();
    dir.close().unwrap();
    assert!(!root.exists());
}

fn spec() -> BindingSpec {
    BindingSpec {
        scheme: Scheme::Https,
        host: "API.Example.COM.".into(),
        port: 443,
        methods: ["POST".into()].into(),
        path_prefix: "/v1/chat".into(),
        injection: Injection::Bearer,
    }
}

#[test]
fn origin_method_and_path_boundaries_refuse_confusion_and_ambiguous_encoding() {
    let spec = spec().canonicalize().unwrap();
    assert_eq!(spec.host, "api.example.com");
    assert!(
        spec.matches(
            Scheme::Https,
            "api.example.com",
            443,
            "POST",
            "/v1/chat/completions?stream=1"
        )
        .unwrap()
    );
    for (scheme, host, port, method, path) in [
        (Scheme::Http, "api.example.com", 443, "POST", "/v1/chat"),
        (Scheme::Https, "evil.example.com", 443, "POST", "/v1/chat"),
        (Scheme::Https, "api.example.com", 8443, "POST", "/v1/chat"),
        (Scheme::Https, "api.example.com", 443, "GET", "/v1/chat"),
        (
            Scheme::Https,
            "api.example.com",
            443,
            "POST",
            "/v1/chat-other",
        ),
    ] {
        assert!(!spec.matches(scheme, host, port, method, path).unwrap());
    }
    for path in [
        "//api.example.com/../v1/chat",
        "/v1/chat/../admin",
        "/v1/chat/%2e%2e/admin",
        "/v1/chat/%252e%252e/admin",
        "/v1/chat%2f..%2fadmin",
        "/v1/chat\\admin",
        "/v1/chat/%0d%0aHost:evil",
        "/v1/chat/%ZZ",
    ] {
        assert!(
            spec.matches(Scheme::Https, "api.example.com", 443, "POST", path)
                .is_err(),
            "{path}"
        );
    }
    let mut reserved = spec.clone();
    reserved.injection = Injection::Header {
        name: "Host".into(),
    };
    assert!(reserved.canonicalize().is_err());
}
