//! Public resolver configuration data. This grants no network authority.
use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;

pub struct ResolverConfig {
    file_name: String,
    contents: String,
}

impl ResolverConfig {
    pub fn new(gateway: Ipv4Addr) -> Self {
        let contents = format!("nameserver {gateway}\noptions timeout:1 attempts:1\n");
        let file_name = format!("resolver-{:x}.conf", Sha256::digest(contents.as_bytes()));
        Self {
            file_name,
            contents,
        }
    }
    pub fn file_name(&self) -> &str {
        &self.file_name
    }
    pub fn contents(&self) -> &str {
        &self.contents
    }
}
