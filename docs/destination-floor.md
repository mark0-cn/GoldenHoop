# Trusted destination floor

Status: the bounded immutable Rust model and portable regressions exist. No destination-floor kernel table, DNS integration, driver provisioning or public capability is implemented yet. The complete M3-M6 objective is unchanged.

`ProtectedDestinations` takes a `DestinationScope` from trusted provisioning: kernel-observed host addresses, administrator-owned control-service addresses and explicit private-subnet exceptions. Virtual control-service IPs must be supplied even when they are absent from host interfaces. A supplied scope is data, not proof of a current kernel observation. User network policy must never populate these administrator fields.

The model bounds input before compilation: 128 host addresses, 64 control addresses and 32 private exceptions, with at most 64 bytes per exception. Exceptions must be canonical, host-bit-free subnets contained in the supported private classes. Public/overbroad subnets, mixed-family mapped forms, unknown fields and command text are refused. Sorted, deduplicated scope data has a version-bound SHA256; that digest is identity data, not authorization or proof of enforcement.

| Class | Meaning |
| --- | --- |
| `Protected` | A pinned host/control address or a built-in hard restriction; private exceptions cannot exempt it |
| `PrivateDenied` | A supported private address without an administrator exception |
| `PrivateException` | Exempt from this floor's private restriction; still requires effective user/ancestor policy and actual installation |
| `Other` | Outside these lists; no public-routability or permission claim |

Private classes include [RFC 1918](https://datatracker.ietf.org/doc/html/rfc1918) IPv4 ranges, [RFC 6598](https://www.rfc-editor.org/info/rfc6598/) shared address space and [RFC 4193](https://www.rfc-editor.org/info/rfc4193/) unique-local IPv6. Hard restrictions cover unspecified/loopback, link-local, multicast/reserved, mapped/compatible IPv6 and deprecated site-local address forms. Classification preserves the native family rather than converting an IPv6 DNS record into an IPv4 private exception.

Known special endpoints include AWS's [IPv4/IPv6 IMDS addresses](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-new-instances.html), Alibaba's [100.100.100.200 metadata service](https://www.alibabacloud.com/help/en/eci/user-guide/obtain-the-metadata-from-a-container-2) and Azure's [168.63.129.16 platform endpoint](https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16). These remain protected even inside a broader private exception. The list does not discover every provider-specific service; deployment-owned control endpoints remain necessary.

The standard [RFC 6052](https://www.rfc-editor.org/info/rfc6052/) and [RFC 8215](https://www.rfc-editor.org/info/rfc8215/) translation prefixes are conservatively protected until their translation path has its own enforcement contract. Custom translation, tunnelling and an allowed remote service's own forwarding behavior are not inferred from this address classifier. Production network profiles must account for their actual topology before claiming a boundary.

Four portable regression groups check independent native boundary/metadata/translation vectors, private exceptions that cannot exempt host/control/metadata addresses, strict parsing and quotas, and deterministic scope identity. These tests establish model behavior only.

Required integration remains:

1. Observe and bind actual host/control topology from the trusted allocator, retain desired scope durably and compare it on restart and mutation.
2. Install a generation-owned immutable packet floor before workload publication, ahead of user/operator allows and established-flow admission. Verify exact scoped semantics and confirm absence on collection.
3. Apply the same floor to DNS address candidates before grant staging or answer publication. A private exception does not create an address or name grant.
4. Prove direct-IP, DNS-derived, IPv4/IPv6, private-exception, metadata/control, replacement, controller-loss and recovery behavior on actual runtimes with live controlled recipients and scoped drop counters. Keep cloud metadata tests synthetic; do not query real instance credentials.
