use goldenhoop_client::*;
use std::time::Duration;
use uuid::Uuid;

pub async fn exercise(client: &Client, sandbox: Uuid, profile: &str) -> Result<Vec<CodeLanguage>> {
    let languages = client
        .profiles()
        .await?
        .into_iter()
        .find(|p| p.id == profile)
        .ok_or(Error::Protocol("language contract profile is missing"))?
        .code_languages;
    assert!(languages.contains(&CodeLanguage::Python));
    for &language in &languages {
        let spec = CodeContextSpec {
            language,
            ..Default::default()
        };
        let key = Uuid::new_v4().to_string();
        let created = client.create_code_context(sandbox, &spec, &key).await?;
        assert_eq!(
            client.create_code_context(sandbox, &spec, &key).await?.id,
            created.id
        );
        let ready = client
            .wait_code_context_ready(created.id, Duration::from_secs(40))
            .await?;
        assert_eq!(ready.spec.language, language);
        assert_eq!(
            ready.kernel_info.as_ref().unwrap()["language_info"]["name"],
            language.as_str()
        );
        let (init, advance, current, exception) = sources(language);
        let result = client.run_code(created.id, &CodeRunSpec::new(init)).await?;
        assert_eq!(result.run.state, CodeRunState::KernelSucceeded);
        let key = Uuid::new_v4().to_string();
        let result = client
            .run_code_with_key(created.id, &CodeRunSpec::new(advance), &key)
            .await?;
        let replay = client
            .run_code_with_key(created.id, &CodeRunSpec::new(advance), &key)
            .await?;
        assert_eq!(result.run.id, replay.run.id);
        assert_eq!(replay.stdout, "42\n");
        assert_eq!(
            client
                .run_code(created.id, &CodeRunSpec::new(current))
                .await?
                .stdout,
            "42\n"
        );
        assert_eq!(
            client
                .run_code(created.id, &CodeRunSpec::new(exception))
                .await?
                .run
                .state,
            CodeRunState::KernelFailed
        );
        client
            .close_code_context(created.id, &Uuid::new_v4().to_string())
            .await?;
        assert_eq!(
            client
                .wait_code_context_closed(created.id, Duration::from_secs(30))
                .await?
                .cleanup,
            CleanupState::Complete
        );
    }
    Ok(languages.into_iter().collect())
}
fn sources(language: CodeLanguage) -> (&'static str, &'static str, &'static str, &'static str) {
    match language {
        CodeLanguage::Python => (
            "value=40",
            "value+=2\nprint(value)",
            "print(value)",
            "raise ValueError('expected')",
        ),
        CodeLanguage::Java => (
            "int value=40;",
            "value+=2; System.out.println(value);",
            "System.out.println(value);",
            "throw new IllegalStateException(\"expected\");",
        ),
        CodeLanguage::Go => (
            "import \"fmt\"\nvalue:=40",
            "value+=2\nfmt.Println(value)",
            "fmt.Println(value)",
            "panic(\"expected\")",
        ),
        CodeLanguage::TypeScript => (
            "var value: number=40;",
            "value+=2; console.log(value);",
            "console.log(value);",
            "throw new Error('expected');",
        ),
        CodeLanguage::JavaScript => (
            "var value=40;",
            "value+=2; console.log(value);",
            "console.log(value);",
            "throw new Error('expected');",
        ),
        CodeLanguage::Bash => (
            "value=40",
            "value=$((value+2)); printf '%s\\n' \"$value\"",
            "printf '%s\\n' \"$value\"",
            "false",
        ),
    }
}
