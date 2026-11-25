//! Filesystem link/race models, not native kernel acceptance.
use super::*;
use std::{fs, os::unix::fs::symlink, path::PathBuf};
struct Fixture {
    directory: tempfile::TempDir,
    allocation: Allocation,
    addresses: EndpointAddresses,
}
impl Fixture {
    fn new() -> Self {
        let generation = uuid::Uuid::new_v4();
        let fixture = Self {
            directory: tempfile::tempdir().unwrap(),
            allocation: Allocation {
                installation_id: uuid::Uuid::new_v4(),
                sandbox_id: uuid::Uuid::new_v4(),
                generation,
                bridge: format!("ghn{}", &generation.simple().to_string()[..12]),
                ifindex: 42,
            },
            addresses: EndpointAddresses {
                mac: "02:00:00:00:00:02".parse().unwrap(),
                ipv4: "10.77.0.2".parse().unwrap(),
                ipv6: Some("fd00:77::2".parse().unwrap()),
            },
        };
        let bridge = fixture.bridge();
        let port = fixture.port();
        fs::create_dir_all(bridge.join("bridge")).unwrap();
        fs::create_dir_all(bridge.join("brif")).unwrap();
        fs::write(bridge.join("ifindex"), "42\n").unwrap();
        fs::create_dir_all(port.join("brport")).unwrap();
        fs::write(port.join("ifindex"), "43\n").unwrap();
        symlink(&bridge, port.join("master")).unwrap();
        symlink(port.join("brport"), bridge.join("brif/veth42")).unwrap();
        fixture
    }
    fn bridge(&self) -> PathBuf {
        self.directory.path().join(&self.allocation.bridge)
    }
    fn port(&self) -> PathBuf {
        self.directory.path().join("veth42")
    }
    fn observe(&self) -> Result<Endpoint, ApiError> {
        observe(self.directory.path(), &self.allocation, &self.addresses)
    }
    fn close(self) {
        let path = self.directory.path().to_owned();
        self.directory.close().unwrap();
        assert!(!path.exists());
    }
}
#[test]
fn sole_bridge_symlink_resolves_to_the_global_port_brport_not_an_ifindex_file_in_brif() {
    let fixture = Fixture::new();
    assert!(!fixture.bridge().join("brif/veth42/ifindex").exists());
    let endpoint = fixture.observe().unwrap();
    assert_eq!(endpoint.port, "veth42");
    assert_eq!(endpoint.ifindex, 43);
    assert_eq!(endpoint.mac, fixture.addresses.mac);
    fixture.close();
}
#[test]
fn missing_multiple_unsafe_or_foreign_bridge_port_links_refuse() {
    for case in 0..4 {
        let fixture = Fixture::new();
        let entry = fixture.bridge().join("brif/veth42");
        match case {
            0 => fs::remove_file(&entry).unwrap(),
            1 => symlink(
                fixture.port().join("brport"),
                fixture.bridge().join("brif/veth43"),
            )
            .unwrap(),
            2 => {
                fs::remove_file(&entry).unwrap();
                symlink(
                    fixture.port().join("brport"),
                    fixture.bridge().join("brif/Veth42"),
                )
                .unwrap();
            }
            _ => {
                fs::remove_file(&entry).unwrap();
                symlink(fixture.bridge().join("bridge"), &entry).unwrap();
            }
        }
        assert!(fixture.observe().is_err(), "case {case}");
        fixture.close();
    }
}
#[test]
fn reused_index_wrong_master_missing_brport_and_nonpositive_indices_refuse() {
    for case in 0..6 {
        let fixture = Fixture::new();
        match case {
            0 => fs::write(fixture.port().join("ifindex"), "42\n").unwrap(),
            1 => fs::write(fixture.bridge().join("ifindex"), "44\n").unwrap(),
            2 => fs::remove_dir(fixture.port().join("brport")).unwrap(),
            3 => fs::write(fixture.port().join("ifindex"), "0\n").unwrap(),
            4 => fs::write(fixture.port().join("ifindex"), "2147483648\n").unwrap(),
            _ => {
                fs::remove_file(fixture.port().join("master")).unwrap();
                fs::create_dir(fixture.port().join("master")).unwrap();
                fs::write(fixture.port().join("master/ifindex"), "44\n").unwrap();
            }
        }
        assert!(fixture.observe().is_err(), "case {case}");
        fixture.close();
    }
}
