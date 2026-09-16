# ThrottleStop driver provenance

The bundled driver is kept unchanged. Its canonical binary identity and signer-certificate identity live in `integrity.json`; code, tests, release scripts, and documentation must not duplicate those hashes.

- Binary: `ThrottleStop_x64.sys` (name is also sourced from `integrity.json`).
- Version observed during provenance review: 3.0.0.0, PE x64, timestamp 2020-10-06.
- Authenticode provenance review: signer TechPowerUp LLC.
- No WDK, custom kernel build, or project-owned signing certificate is required.
- Each read session owns a unique demand-start service. It never reuses or modifies ThrottleStop's service.
- A valid signature does not prove that every Windows 11 Code Integrity policy will allow loading.
- This private project does not assert public redistribution rights. Consult the applicable ThrottleStop/TechPowerUp terms before distributing the binary publicly.

Static review of the pinned binary found MSR, port I/O, PCI, and physical-memory operations. The application exposes only PCI reads and a tightly scoped SPI BIOS-read path. It does not expose arbitrary physical-memory access, WRMSR, flash erase, or flash write to the UI. See `docs/DRIVER-RESEARCH.md`.

## Runtime authenticity checks

Before the service is created, the application verifies the exact binary SHA-256 from `integrity.json` and validates Windows Authenticode trust through `WinVerifyTrust`. The extracted driver is then held with write/delete sharing denied until the kernel service stops, closing the ordinary verify-to-load replacement race.

The release script independently reads the same manifest, validates the binary hash, requires a valid Authenticode signature, and pins the signer certificate hash from that manifest before building. These controls do not defend against an attacker who already has administrator/kernel control or who can replace and re-sign the application itself.
