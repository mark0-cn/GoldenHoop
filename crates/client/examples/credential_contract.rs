//! Actual-server SDK gate. Private input is never printed or automatically retried.
use goldenhoop_client::{Client, WriteCredential};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 3 {
        return Err("expected sandbox, binding and private request file".into());
    }
    let sandbox = Uuid::parse_str(&args[0])?;
    let binding = Uuid::parse_str(&args[1])?;
    let input = goldenhoop_credentials::read_private_config(std::path::Path::new(&args[2]))?;
    let input: WriteCredential =
        serde_json::from_slice(&input).map_err(|_| "invalid private credential input")?;
    let client = Client::new(
        &std::env::var("GOLDENHOOP_ENDPOINT")?,
        &std::env::var("GOLDENHOOP_API_TOKEN")?,
    )?;
    let created = client.put_credential(sandbox, binding, &input).await?;
    let got = client.credential(sandbox, binding).await?;
    assert_eq!(got.id, created.id);
    assert_eq!(got.revision, created.revision);
    assert!(
        client
            .credentials(sandbox)
            .await?
            .iter()
            .any(|r| r.id == binding)
    );
    let ca = client.credential_ca(sandbox).await?;
    println!(
        "{}",
        serde_json::json!({"binding":created,"public_ca_sha256":format!("{:x}",Sha256::digest(ca.certificate_pem.as_bytes()))})
    );
    Ok(())
}
