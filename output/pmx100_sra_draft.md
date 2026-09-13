# Security Risk Assessment — draft

One entry per threat. Each entry carries CVSS v3.1 scoring, gap analysis against FDA / IEC / AAMI / NIST, and proposed doc + code changes.

---

## DF-BLEPAIR-I · Unencrypted BLE Pairing Traffic Capture
**STRIDE:** I   **CVSS:** 8.1 High   **Priority:** P1   **Effort:** 1.5 eng-weeks
**Residual risk:** Medium — Implementing LE Secure Connections will mitigate the threat, but residual risk remains due to potential implementation flaws.

The threat of unencrypted BLE pairing traffic capture is critical due to the use of 'Just Works' mode without encryption, allowing adversaries to intercept keys. Implementing BLE LE Secure Connections with numeric comparison will address this vulnerability, enhancing security during pairing.

**Existing controls (legacy):**
- `CTRL:tls-1-0-for-encrypted-data-in-transit-legacy` — TLS 1.0 for encrypted data-in-transit (legacy)

**Gap analysis:**

| Clause | Verdict | Reason |
|---|---|---|
| `FDA-2023-V.B.6` | **MISSING** | The device uses 'Just Works mode' for BLE pairing with 'no encryption during pairing', directly violating the clause's requirement for authenticated, encrypted mechanisms and LE Secure Connections. No listed control addresses BLE pairing security. |
| `FDA-2023-V.B.9` | **MISSING** | The provided threat and existing controls do not address physical port or debug interface hardening, leaving this clause unaddressed. |
| `FDA-2023-V.B.5` | **PARTIAL** | The device uses TLS 1.0 for encrypted data-in-transit, which is explicitly outdated and insufficient as the clause requires TLS 1.2 or later for transport-layer security. |
| `FDA-2023-V.B.3` | **MISSING** | The provided threat and existing controls do not address cryptographic integrity of firmware or update mechanisms, leaving this clause unaddressed. |
| `FDA-2023-V.B.4` | **PARTIAL** | The device uses TLS 1.0 for data-in-transit, which is not considered 'current, standards-based' encryption. Additionally, the threat highlights 'no encryption during pairing' for BLE, directly violating confidentiality requirements during transmission. |
| `FDA-2023-V.B.8` | **MISSING** | The provided threat and existing controls do not address audit logging or event traceability, leaving this clause unaddressed. |

**Proposed controls:**
- `CTRL:PROPOSED:ble-le-secure-connections` — Implement BLE LE Secure Connections with numeric comparison or out-of-band authentication for pairing.

**Proposed doc changes:**
- SRS.md · **add** `SRS-SEC-NEW-01` — The device shall use BLE LE Secure Connections with numeric comparison or out-of-band authentication for all pairing processes to ensure encrypted and authenticated communication.

**Proposed code changes:**

`firmware/ble_pairing.c:0` (create_file)
```
#include <ble_secure_connections.h>

void setup_ble_pairing() {
    ble_secure_connections_enable();
    ble_set_authentication_method(NUMERIC_COMPARISON);
}

```

---

## DF-BLEVITALS-T · BLE Vitals Spoofing via MITM
**STRIDE:** T   **CVSS:** 8.8 High   **Priority:** P1   **Effort:** 1.5 eng-weeks
**Residual risk:** Medium — Implementing BLE LE Secure Connections reduces spoofing risk but does not eliminate it entirely.

The BLE Vitals Spoofing threat allows attackers to alter vital signs data by exploiting the lack of cryptographic protection. Implementing BLE LE Secure Connections will provide cryptographic signatures and message authentication, reducing the risk of spoofing.

**Existing controls (legacy):**
- `CTRL:no-cryptographic-signatures-or-crc-validation-for-ble-notifications-relies-on-ju` — No cryptographic signatures or CRC validation for BLE notifications; relies on 'Just Works' BLE trust model

**Proposed controls:**
- `CTRL:PROPOSED:ble-le-secure-connections` — Implement BLE LE Secure Connections with cryptographic signatures for message authentication.

**Proposed doc changes:**
- SDS.md · **add** `SDS-SEC-NEW-01` — Implement BLE LE Secure Connections to ensure cryptographic signatures and message authentication for BLE notifications.

**Proposed code changes:**

`firmware/ble_security.c:0` (create_file)
```
// Implement BLE LE Secure Connections
void setup_ble_security() {
    // Code to initialize BLE LE Secure Connections
}

```

---

## DF-EMR-T · Man-in-the-middle HL7/FHIR replay
**STRIDE:** T   **CVSS:** 10.0 Critical   **Priority:** P0   **Effort:** 2 eng-weeks
**Residual risk:** Low — Implementing TLS 1.2+ with certificate pinning and SHA-256 integrity checks reduces risk significantly.

The current use of TLS 1.0 with weak cipher suites exposes HL7/FHIR data to man-in-the-middle attacks. By upgrading to TLS 1.2+ with certificate pinning and implementing SHA-256 integrity checks, we can significantly enhance the security of data in transit, mitigating the threat effectively.

**Existing controls (legacy):**
- `CTRL:tls-1-0-with-system-ca-bundle-for-cert-validation` — TLS 1.0 with system CA bundle for cert validation

**Proposed controls:**
- `CTRL:PROPOSED:tls-1-2-with-cert-pinning` — Upgrade to TLS 1.2+ with certificate pinning for secure communication.
- `CTRL:PROPOSED:sha-256-integrity-check` — Implement SHA-256 integrity checks for HL7/FHIR data in transit.

**Proposed doc changes:**
- SDS.md · **add** `SDS-SEC-NEW-01` — Implement TLS 1.2+ with certificate pinning for all HL7/FHIR communications to prevent man-in-the-middle attacks.
- SDS.md · **add** `SDS-SEC-NEW-02` — Use SHA-256 for integrity checks on HL7/FHIR data to ensure data integrity during transit.

**Proposed code changes:**

`firmware/network_security.c:0` (create_file)
```
#include <openssl/ssl.h>
#include <openssl/err.h>

void setup_secure_connection() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    // Load pinned certificates
    // Additional setup code
}

```
`firmware/data_integrity.c:0` (create_file)
```
#include <openssl/sha.h>

void check_data_integrity(const unsigned char *data, size_t len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);
    // Compare hash with expected value
}

```

---

## DF-SPICONFIG-D · SPI bus starvation attack
**STRIDE:** D   **CVSS:** 10.0 Critical   **Priority:** P0   **Effort:** 2 eng-weeks
**Residual risk:** Medium — Proposed controls will mitigate the attack but not eliminate all risks due to potential new attack vectors.

The SPI bus starvation attack poses a critical risk by potentially crashing the Safety MCU. Existing controls are insufficient, as they lack secure boot and strong authentication. Proposed changes include implementing secure boot and adding authentication for SPI commands to mitigate this threat.

**Existing controls (legacy):**
- `CTRL:lightweight-range-check-at-safety-mcu` — Lightweight range check at Safety MCU

**Gap analysis:**

| Clause | Verdict | Reason |
|---|---|---|
| `FDA-2023-V.B.9` | **MISSING** | The existing control 'Lightweight range check at Safety MCU' addresses input validation for the SPI bus, not the hardening of debug interfaces or service ports with strong authentication and auditability as required by this clause. |
| `FDA-2023-V.B.7` | **MISSING** | The existing control is a lightweight runtime check on SPI data, not a secure boot chain with cryptographic verification of firmware or runtime integrity monitoring of critical safety code against unauthorized modification. |
| `FDA-2023-V.B.3` | **MISSING** | The existing control is a lightweight range check for SPI data, not cryptographic authenticity verification for firmware images or update artifacts. The clause explicitly states that CRC (mentioned in the threat) is insufficient for firmware integrity. |
| `FDA-2023-V.A.1` | **MISSING** | This clause requires documentation of a Secure Product Development Framework (SPDF). The existing control is a technical mitigation, not evidence of an SPDF or its execution. |
| `NIST-800-193-5.2` | **PARTIAL** | The 'Lightweight range check at Safety MCU' control performs a basic runtime integrity check on incoming SPI data, which can detect some forms of 'corruption' (invalid inputs) that could affect platform operation. However, it is 'lightweight' and not comprehensive for detecting corruption of firmwar |
| `AAMI-TIR57-6.3.2` | **PRESENT** | The 'Lightweight range check at Safety MCU' control is an implemented risk-control measure directly addressing the 'SPI bus starvation attack' threat, which has safety implications ('Safety MCU', 'safety-critical updates'). This demonstrates that a control has been specified and implemented for a se |

**Proposed controls:**
- `CTRL:PROPOSED:secure-boot` — Implement secure boot with cryptographic verification of firmware.
- `CTRL:PROPOSED:spi-authentication` — Add strong authentication for SPI commands to prevent unauthorized access.

**Proposed doc changes:**
- SDS.md · **add** `SDS-SEC-NEW-01` — Implement secure boot with cryptographic verification to ensure only authorized firmware executes.

**Proposed code changes:**

`firmware/spi_handler.c:0` (create_file)
```
// Implement strong authentication for SPI commands
void authenticate_spi_command() {
    // Authentication logic here
}
```

---

## DF-SPIFW-T · Spoofed SPI firmware chunk injection
**STRIDE:** T   **CVSS:** 9.8 Critical   **Priority:** P0   **Effort:** 2 eng-weeks
**Residual risk:** Medium — Implementing cryptographic signatures will significantly reduce the risk of spoofing.

The threat of spoofed SPI firmware chunk injection is critical due to the lack of cryptographic integrity checks. Implementing Ed25519-based cryptographic signatures will ensure that only authentic firmware chunks are accepted, mitigating the risk of malicious code injection.

**Existing controls (legacy):**
- `CTRL:crc-16-ccitt-checksum-on-each-chunk` — CRC-16-CCITT checksum on each chunk

**Proposed controls:**
- `CTRL:PROPOSED:cryptographic-signatures` — Implement cryptographic signatures for firmware chunks using Ed25519.

**Proposed doc changes:**
- SDS.md · **add** `SDS-SEC-NEW-01` — Introduce cryptographic signatures for firmware chunks using Ed25519 to ensure integrity and authenticity.

**Proposed code changes:**

`firmware/ota_update.c:0` (create_file)
```
// Implement cryptographic signature verification for OTA updates
#include <ed25519.h>

void verify_firmware_chunk_signature(const uint8_t *chunk, size_t chunk_size) {
    // Verify the signature of the chunk
    // ... (implementation details)
}

```

---

## DF-SPIVITALS-T · Spoofed Vital Sign Frames via SPI
**STRIDE:** T   **CVSS:** 7.6 High   **Priority:** P1   **Effort:** 2 eng-weeks
**Residual risk:** Medium — Implementing cryptographic validation will significantly reduce the risk of spoofed SPI frames.

The threat of spoofed SPI frames can lead to false alarms or incorrect patient readings. Current CRC-16-CCITT checks are insufficient for modern security standards. Implementing HMAC-SHA-256 for cryptographic validation will enhance data integrity and authenticity, reducing the risk of spoofed frames.

**Existing controls (legacy):**
- `CTRL:crc-16-ccitt-checksum-validation-on-each-frame` — CRC-16-CCITT checksum validation on each frame

**Gap analysis:**

| Clause | Verdict | Reason |
|---|---|---|
| `FDA-2023-V.B.3` | **MISSING** | This clause specifically addresses cryptographic integrity for firmware and update mechanisms. The threat and existing control relate to runtime data integrity of SPI frames, not firmware. Therefore, no existing control addresses this clause's intent. |
| `FDA-2023-V.B.7` | **MISSING** | This clause requires secure boot and runtime integrity monitoring of critical safety code. The existing control only addresses integrity of SPI data frames during runtime, not the integrity of the executing code itself or the boot process. |
| `FDA-2023-V.B.6` | **MISSING** | This clause pertains to wireless pairing and link security. The threat under analysis and the associated control are specific to SPI (Serial Peripheral Interface) communication, which is a wired internal bus, not a wireless link. |
| `NIST-800-193-5.2` | **PARTIAL** | The existing CRC-16-CCITT checksum validation detects corruption of SPI data frames at runtime, which partially addresses the clause's requirement for detecting corruption of 'firmware data'. However, CRC is considered a legacy integrity check and not sufficient for modern security standards, especi |
| `FDA-2023-V.A.1` | **MISSING** | This clause requires a documented Secure Product Development Framework (SPDF). The threat and existing control are technical details about SPI data integrity, not evidence of an overarching development process framework. |
| `FDA-2023-V.B.9` | **MISSING** | This clause focuses on securing physical ports and debug interfaces. The threat and existing control are concerned with the integrity of SPI data frames during internal communication, which is unrelated to physical port hardening. |

**Proposed controls:**
- `CTRL:PROPOSED:spi-crypto-validation` — Implement cryptographic validation of SPI frames using HMAC-SHA-256.

**Proposed doc changes:**
- SDS.md · **add** `SDS-SEC-NEW-01` — Introduce HMAC-SHA-256 for cryptographic validation of SPI frames to ensure data integrity and authenticity.

**Proposed code changes:**

`firmware/safety_mcu/spi_slave.c:84` (modify)
```
uint8_t hmac_sha256_key[] = { /* key bytes */ };
uint8_t hmac_sha256_result[32];
// Compute HMAC-SHA-256 on received frame
digest_hmac_sha256(received_frame, frame_length, hmac_sha256_key, sizeof(hmac_sha256_key), hmac_sha256_result);
// Validate HMAC-SHA-256 result
```

---

## DF-USBIN-T · Malicious Firmware Overwrite via USB
**STRIDE:** T   **CVSS:** 6.8 Medium   **Priority:** P2   **Effort:** 1 eng-weeks
**Residual risk:** Medium — Without cryptographic signatures, firmware integrity is not fully assured.

The threat of malicious firmware overwrite via USB is currently not mitigated. The existing CRC-32 checksum verification is insufficient as it does not prevent unauthorized firmware modifications. Implementing cryptographic signature verification using Ed25519 will ensure firmware authenticity and integrity, reducing the risk of malicious overwrites.

**Existing controls (legacy):**
- `CTRL:crc-32-checksum-verification-on-firmware-file` — CRC-32 checksum verification on firmware file

**Proposed controls:**
- `CTRL:PROPOSED:firmware-signature-verification` — Implement cryptographic signature verification for firmware updates using Ed25519.

**Proposed doc changes:**
- SRS.md · **add** `SRS-SEC-NEW-01` — The system shall verify firmware updates using cryptographic signatures (Ed25519) to ensure authenticity and integrity.

**Proposed code changes:**

`firmware/update_handler.c:0` (create_file)
```
#include <ed25519.h>

void verify_firmware_signature(const char *firmware_path) {
    // Implementation of signature verification using Ed25519
}

```

---

## DF-USBOUT-I · USB Drive Patient Data Leak
**STRIDE:** I   **CVSS:** 0.0 None   **Priority:** P2   **Effort:** 0 eng-weeks
**Residual risk:** Medium — TCR parse_error — reviewer must inspect raw LLM response.

TCR agent could not produce a valid entry: [citation_verify] proposed_code_changes.path: 'firmware/logging.c' (action=modify) not present as CodeArtifact in graph; [citation_verify] proposed_code_changes.path: 'firmware/usb_export.c' (action=m

> **PARSE ERROR** — raw LLM output preserved in JSON file.

---

## DS-BLEKEY-T · eMMC BLE key tampering via JTAG
**STRIDE:** T   **CVSS:** 6.8 Medium   **Priority:** P2   **Effort:** 1.5 eng-weeks
**Residual risk:** Medium — Physical access controls reduce risk, but JTAG access still allows tampering.

The threat involves tampering with BLE keys via JTAG access to the eMMC. Existing physical access controls are insufficient. Proposed controls include disabling JTAG in production and adding cryptographic integrity checks for BLE keys.

**Existing controls (legacy):**
- `CTRL:physical-access-controls-lockable-enclosure` — Physical access controls (lockable enclosure)

**Proposed controls:**
- `CTRL:PROPOSED:integrity-checks` — Implement cryptographic integrity checks for BLE keys stored on eMMC.
- `CTRL:PROPOSED:jtag-disable` — Disable JTAG interface in production firmware.

**Proposed doc changes:**
- SDS.md · **add** `SDS-SEC-NEW-01` — Implement cryptographic integrity checks for BLE keys stored on eMMC to prevent unauthorized modifications.

**Proposed code changes:**

`firmware/jtag.c:0` (create_file)
```
// Disable JTAG interface in production builds
void disable_jtag() {
    // Platform-specific code to disable JTAG
}

```
`firmware/ble_key_storage.c:0` (create_file)
```
// Implement integrity checks for BLE keys
void check_ble_key_integrity() {
    // Code to verify cryptographic integrity of BLE keys
}

```

---

## DS-BOOT-T · Bootloader partition hijack via eMMC write
**STRIDE:** T   **CVSS:** 0.0 None   **Priority:** P2   **Effort:** 0 eng-weeks
**Residual risk:** Medium — TCR parse_error — reviewer must inspect raw LLM response.

TCR agent could not produce a valid entry: [citation_verify] proposed_code_changes.path: 'firmware/bootloader.c' (action=add) not present as CodeArtifact in graph; [citation_verify] proposed_code_changes.path: 'firmware/integrity_monitor.c' (a

> **PARSE ERROR** — raw LLM output preserved in JSON file.

---

## DS-FWB-T · eMMC firmware slot B overwrite
**STRIDE:** T   **CVSS:** 0.0 None   **Priority:** P2   **Effort:** 0 eng-weeks
**Residual risk:** Medium — TCR parse_error — reviewer must inspect raw LLM response.

TCR agent could not produce a valid entry: [citation_verify] proposed_code_changes.path: 'firmware/emmc_write.c' (action=modify) not present as CodeArtifact in graph

> **PARSE ERROR** — raw LLM output preserved in JSON file.

---

## DS-SDLOG-T · SD card log overwrite
**STRIDE:** T   **CVSS:** 7.6 High   **Priority:** P1   **Effort:** 3 eng-weeks
**Residual risk:** Medium — Implementing proposed controls will reduce the risk of log tampering but not eliminate physical access threats entirely.

The threat of SD card log overwrite is critical due to the potential for tampering with patient logs. Existing controls are insufficient as they only address physical access. Proposed controls include implementing tamper-evident logging, secure boot, and runtime integrity checks to mitigate this threat.

**Existing controls (legacy):**
- `CTRL:physical-access-control-via-rubber-cover-slot` — Physical access control via rubber-cover slot

**Gap analysis:**

| Clause | Verdict | Reason |
|---|---|---|
| `FDA-2023-V.B.8` | **MISSING** | The existing physical access control via a rubber cover does not provide tamper-evident properties for the logs themselves, which is a core requirement of this clause. The threat explicitly describes overwriting logs, indicating a lack of such properties. |
| `NIST-800-193-5.2` | **MISSING** | The existing control only addresses physical access to the SD card slot and does not provide any mechanism for detecting corruption of firmware, firmware data, or critical platform configuration as required by this clause. |
| `NIST-800-193-4.2` | **MISSING** | The existing control addresses physical access to the SD card slot and provides no mechanism for authenticating firmware updates or preventing rollbacks, which are the core requirements of this clause. |
| `FDA-2023-V.B.3` | **MISSING** | The existing control only addresses physical access to the SD card slot and does not provide cryptographic integrity verification for firmware or update artifacts as required by this clause. |
| `FDA-2023-V.A.1` | **MISSING** | This clause requires documentation of a Secure Product Development Framework (SPDF). The existing control is a physical device feature and does not provide evidence of an SPDF or its execution. |
| `FDA-2023-V.B.7` | **MISSING** | The existing control only addresses physical access to the SD card slot and does not implement a secure boot chain or runtime integrity monitoring as required by this clause. |

**Proposed controls:**
- `CTRL:PROPOSED:tamper-evident-logging` — Implement tamper-evident logging with cryptographic signatures for log files.
- `CTRL:PROPOSED:secure-boot` — Implement secure boot to ensure only verified firmware executes.
- `CTRL:PROPOSED:firmware-integrity-check` — Add runtime integrity checks for firmware and critical configurations.

**Proposed doc changes:**
- SDS.md · **add** `SDS-SEC-NEW-01` — Introduce tamper-evident logging mechanisms using cryptographic signatures to ensure log integrity and traceability.
- SDS.md · **add** `SDS-SEC-NEW-02` — Implement secure boot to ensure only cryptographically verified firmware is executed.
- SDS.md · **add** `SDS-SEC-NEW-03` — Add runtime integrity checks for firmware and critical configurations to detect unauthorized modifications.

**Proposed code changes:**

`firmware/logging.c:0` (create_file)
```
// Implement tamper-evident logging
#include <crypto.h>
void log_event(const char* event) {
    // Log event with cryptographic signature
}
```
`firmware/boot.c:0` (create_file)
```
// Implement secure boot
#include <secure_boot.h>
void boot_sequence() {
    // Verify firmware signature before execution
}
```
`firmware/integrity_check.c:0` (create_file)
```
// Implement runtime integrity checks
#include <integrity.h>
void check_integrity() {
    // Perform integrity checks on firmware and configurations
}
```

---

## DS-STAGING-T · Corrupt OTA staging firmware
**STRIDE:** T   **CVSS:** 7.6 High   **Priority:** P1   **Effort:** 1.5 eng-weeks
**Residual risk:** Medium — Implementing cryptographic signatures will significantly reduce the risk of firmware corruption.

The threat of corrupt OTA staging firmware can lead to crashes or silent corruption. Current CRC checks are insufficient. Implementing cryptographic signatures will ensure firmware authenticity and integrity, reducing the risk of exploitation.

**Existing controls (legacy):**
- `CTRL:crc-16-32-checksums-on-firmware-files` — CRC-16/32 checksums on firmware files

**Proposed controls:**
- `CTRL:PROPOSED:cryptographic-signatures` — Implement cryptographic signatures for firmware images to ensure authenticity and integrity.

**Proposed doc changes:**
- SDS.md · **add** `SDS-SEC-NEW-01` — All firmware images must be signed using Ed25519 to ensure authenticity and integrity during OTA updates.

**Proposed code changes:**

`firmware/ota_update.c:0` (create_file)
```
// Implement cryptographic signature verification using Ed25519 for OTA updates
#include <ed25519.h>

void verify_firmware_signature(const char *firmware_path) {
    // Load firmware and signature
    // Verify signature
    // Proceed with update if valid
}
```

---

## DS-VITALS-T · eMMC vitals log corruption via JTAG
**STRIDE:** T   **CVSS:** 7.6 High   **Priority:** P2   **Effort:** 2 eng-weeks
**Residual risk:** Medium — Proposed controls will reduce risk of unauthorized eMMC access but not eliminate it entirely.

The threat involves potential corruption of the eMMC vitals log via the JTAG interface. Existing physical controls are insufficient. Proposed controls include implementing secure boot and disabling JTAG in production to mitigate this risk.

**Existing controls (legacy):**
- `CTRL:physical-access-control-with-tamper-evident-seals` — Physical access control with tamper-evident seals

**Proposed controls:**
- `CTRL:PROPOSED:secure-boot` — Implement secure boot to verify firmware integrity and authenticity.
- `CTRL:PROPOSED:jtag-lockdown` — Disable JTAG interface in production firmware to prevent unauthorized access.

**Proposed doc changes:**
- SDS.md · **add** `SDS-SEC-NEW-01` — Implement secure boot to ensure only authenticated firmware is executed, preventing unauthorized modifications.
- SDS.md · **add** `SDS-SEC-NEW-02` — Disable JTAG interface in production to prevent unauthorized access to eMMC.

**Proposed code changes:**

`firmware/bootloader.c:0` (create_file)
```
// Implement secure boot verification
void secure_boot_check() {
    // Code to verify firmware signature
}

```
`firmware/jtag.c:0` (create_file)
```
// Disable JTAG interface
void disable_jtag() {
    // Code to disable JTAG
}

```

---

## E-BIOMED-S · USB Service Port Credential Spoofing
**STRIDE:** S   **CVSS:** 7.6 High   **Priority:** P0   **Effort:** 4 eng-weeks
**Residual risk:** Medium — Implementing strong authentication and integrity checks will significantly reduce the risk of unauthorized access and undetected modifications.

The USB service port is vulnerable due to default credentials, allowing unauthorized access and undetected modifications. Proposed controls include implementing strong authentication, digital signature verification for firmware updates, integrity detection mechanisms, and comprehensive audit logging to mitigate these risks.

**Existing controls (legacy):**
- `CTRL:physical-access-control-with-locked-cabinet` — Physical access control with locked cabinet

**Gap analysis:**

| Clause | Verdict | Reason |
|---|---|---|
| `FDA-2023-V.B.9` | **PARTIAL** | The physical access control (locked cabinet) provides some protection, but the device uses default `service/service` credentials for the USB service port, failing the 'strong authentication' requirement. |
| `NIST-800-193-4.2` | **MISSING** | There are no listed controls for authenticating firmware updates via digital signatures or preventing rollback, which are explicit requirements of this clause. The threat indicates firmware can be modified without detection. |
| `NIST-800-193-5.2` | **MISSING** | The threat explicitly states firmware/configuration modification can occur 'without detection,' indicating a lack of controls for platform integrity detection as required by this clause. |
| `FDA-2023-V.B.1` | **PARTIAL** | The device uses default `service/service` credentials for the USB service port, which directly violates the clause's requirement that 'Default or shared credentials shall not be permitted for production deployment.' |
| `FDA-2023-V.B.3` | **MISSING** | There are no listed controls for cryptographic authenticity verification of firmware images or update artifacts, and the threat indicates modifications can occur without detection. |
| `FDA-2023-V.B.8` | **MISSING** | The threat describes configuration and firmware modification occurring 'without detection,' indicating a lack of security-relevant event logging, tamper-evident properties, or exportability. |

**Proposed controls:**
- `CTRL:PROPOSED:strong-authentication` — Implement strong authentication mechanisms for USB service port access, replacing default credentials with unique, non-default credentials.
- `CTRL:PROPOSED:firmware-signature-verification` — Implement digital signature verification for firmware updates using a public key rooted in a trusted key store.
- `CTRL:PROPOSED:integrity-detection` — Implement platform integrity detection mechanisms to identify unauthorized firmware or configuration changes.
- `CTRL:PROPOSED:audit-logging` — Implement audit logging for security-relevant events, ensuring logs are tamper-evident and exportable.

**Proposed doc changes:**
- SRS.md · **add** `SRS-SEC-NEW-01` — The device shall enforce strong authentication for all service port access, replacing default credentials with unique, non-default credentials.
- SDS.md · **add** `SDS-SEC-NEW-01` — The system shall verify digital signatures on firmware updates using a public key rooted in a trusted key store before applying updates.
- SDS.md · **add** `SDS-SEC-NEW-02` — The system shall implement integrity detection mechanisms to identify unauthorized changes to firmware or configuration.
- SDS.md · **add** `SDS-SEC-NEW-03` — The system shall log security-relevant events, ensuring logs are tamper-evident and exportable in a machine-readable format.

**Proposed code changes:**

`firmware/authentication.c:0` (create_file)
```
// Implement strong authentication for USB service port
void authenticate_service_port() {
    // Replace default credentials with unique, non-default credentials
    // Implement authentication logic here
}
```
`firmware/firmware_update.c:0` (create_file)
```
// Implement digital signature verification for firmware updates
void verify_firmware_signature() {
    // Verify digital signature using public key
    // Implement verification logic here
}
```
`firmware/integrity_check.c:0` (create_file)
```
// Implement integrity detection mechanisms
void check_integrity() {
    // Detect unauthorized changes to firmware or configuration
    // Implement detection logic here
}
```
`firmware/audit_logging.c:0` (create_file)
```
// Implement audit logging for security-relevant events
void log_security_event() {
    // Ensure logs are tamper-evident and exportable
    // Implement logging logic here
}
```

---

## E-PATIENT-S · Patient-sensor data injection via spoofed probes
**STRIDE:** S   **CVSS:** 5.3 Medium   **Priority:** P1   **Effort:** 2 eng-weeks
**Residual risk:** Medium — After implementing cryptographic validation, the risk of spoofed probes is reduced but not eliminated due to potential new attack vectors.

The threat of patient-sensor data injection via spoofed probes is critical due to the lack of cryptographic validation. Proposed controls include implementing BLE LE Secure Connections and cryptographic validation for sensor inputs to ensure authenticity and integrity. These measures will significantly reduce the risk of data injection attacks.

**Existing controls (legacy):**
- `CTRL:physical-probe-authentication-via-visual-inspection-only-no-cryptographic-signat` — Physical probe authentication via visual inspection only (no cryptographic signatures or device binding)

**Gap analysis:**

| Clause | Verdict | Reason |
|---|---|---|
| `FDA-2023-V.B.6` | **MISSING** | The threat explicitly mentions a 'BLE-spoofing cuff' and the device's lack of cryptographic validation for sensor inputs. The clause requires authenticated, encrypted wireless pairing, specifically LE Secure Connections for BLE. The existing control is for physical probe visual inspection, not wirel |
| `FDA-2023-V.B.4` | **MISSING** | The threat 'Patient-sensor data injection via spoofed probes' primarily concerns data integrity and authenticity, not confidentiality. The existing control addresses physical authentication, not encryption for data confidentiality at rest or in transit. |
| `NIST-800-193-5.2` | **MISSING** | The clause requires detection of corruption in firmware code, data, and platform configuration. The threat, however, is focused on the integrity of sensor inputs via spoofed probes, which is a different domain of integrity. No existing control addresses platform integrity detection. |
| `FDA-2023-V.B.9` | **MISSING** | The clause addresses the security of debug interfaces and service ports. The threat under analysis, 'Patient-sensor data injection via spoofed probes,' and the existing control are unrelated to these specific hardware interfaces. |
| `AAMI-TIR57-7.1` | **MISSING** | This clause requires a post-market security surveillance process. The provided threat and existing control describe a technical vulnerability and a specific technical (or lack thereof) mitigation, not an organizational post-market process. |
| `FDA-2023-V.B.7` | **MISSING** | The clause mandates secure boot and runtime integrity monitoring for firmware and critical safety code. The threat, 'Patient-sensor data injection via spoofed probes,' concerns the integrity of sensor inputs, which is a distinct issue from the device's boot process or internal code integrity. |

**Proposed controls:**
- `CTRL:PROPOSED:ble-secure-connections` — Implement BLE LE Secure Connections with numeric comparison or out-of-band authentication for all sensor inputs.
- `CTRL:PROPOSED:crypto-validation-sensors` — Add cryptographic validation for all sensor inputs to ensure authenticity and integrity.

**Proposed doc changes:**
- SRS.md · **add** `SRS-SEC-NEW-01` — All sensor inputs must be authenticated and encrypted using BLE LE Secure Connections with numeric comparison or out-of-band authentication.

**Proposed code changes:**

`firmware/sensor_auth.c:0` (create_file)
```
// Implement BLE LE Secure Connections for sensor authentication
#include <ble_secure.h>

void authenticate_sensor_input() {
    // Code to initiate BLE LE Secure Connections
    // with numeric comparison or out-of-band authentication
}

```

---

## P-EMR-E · EMR Client Privilege Escalation via JTAG
**STRIDE:** E   **CVSS:** 7.6 High   **Priority:** P1   **Effort:** 3 eng-weeks
**Residual risk:** Medium — Implementing secure boot and strong authentication for JTAG reduces risk but physical access remains a concern.

The threat of privilege escalation via JTAG is partially mitigated by existing controls, but lacks strong authentication and secure boot. Proposed controls include implementing strong authentication for JTAG, a secure boot chain, and cryptographic signature verification for firmware updates to enhance security.

**Existing controls (legacy):**
- `CTRL:jtag-enabled-with-default-credentials` — JTAG enabled with default credentials

**Gap analysis:**

| Clause | Verdict | Reason |
|---|---|---|
| `FDA-2023-V.B.9` | **PARTIAL** | The JTAG interface, a debug interface, is enabled and protected only by default credentials. This does not constitute 'strong authentication' or adequate protection against unauthorized access as required by the clause. |
| `FDA-2023-V.B.2` | **MISSING** | No existing control addresses the implementation of role-based authorization, principle of least privilege, or separation of administrative and clinical functions for users and services as required by this clause. |
| `NIST-800-193-4.2` | **MISSING** | No existing control describes cryptographic signature verification for firmware updates, a trusted key store, or rollback protection, which are all explicit requirements of this clause. |
| `FDA-2023-V.B.7` | **MISSING** | No existing control implements a secure boot chain with cryptographically verified firmware or runtime integrity monitoring, which are core requirements of this clause. |
| `FDA-2023-V.B.6` | **MISSING** | The existing control addresses JTAG access, which is unrelated to wireless pairing and link security requirements specified in this clause. |
| `NIST-800-193-4.3` | **MISSING** | No existing control describes a Root of Trust for Update (RTU) or its protection against unauthorized modification, which are explicit requirements of this clause. |

**Proposed controls:**
- `CTRL:PROPOSED:secure-jtag-authentication` — Implement strong authentication for JTAG access using unique credentials per device.
- `CTRL:PROPOSED:secure-boot` — Implement a secure boot chain to ensure only verified firmware executes.
- `CTRL:PROPOSED:firmware-signature-verification` — Implement cryptographic signature verification for firmware updates.

**Proposed doc changes:**
- SDS.md · **add** `SDS-SEC-NEW-01` — The system shall implement strong authentication for JTAG access, ensuring unique credentials per device to prevent unauthorized access.
- SDS.md · **add** `SDS-SEC-NEW-02` — The system shall implement a secure boot chain to ensure only cryptographically verified firmware is executed.
- SDS.md · **add** `SDS-SEC-NEW-03` — The system shall verify the cryptographic signature of firmware updates before application to ensure authenticity and integrity.

**Proposed code changes:**

`firmware/jtag_auth.c:0` (create_file)
```
// Implement strong authentication for JTAG
void authenticate_jtag() {
    // Code for unique credential verification
}

```
`firmware/secure_boot.c:0` (create_file)
```
// Implement secure boot chain
void secure_boot() {
    // Code for verifying firmware integrity
}

```
`firmware/firmware_update.c:0` (create_file)
```
// Implement firmware signature verification
void verify_firmware_signature() {
    // Code for signature verification
}

```

---

## P-EMR-I · EMR Credential Exposure via Plaintext
**STRIDE:** I   **CVSS:** 9.1 Critical   **Priority:** P0   **Effort:** 2 eng-weeks
**Residual risk:** Medium — Implementing encryption and authentication reduces risk, but residual risk remains due to potential implementation flaws.

The threat of credential exposure via plaintext transmission is critical, as it allows for easy interception and misuse. Implementing TLS 1.2+ for network communications and BLE LE Secure Connections will encrypt credentials, significantly reducing the risk. Removing default credentials further strengthens security.

**Existing controls (legacy):**
- `CTRL:physical-protection-only-no-network-encryption-for-credentials` — Physical protection only (no network encryption for credentials)

**Gap analysis:**

| Clause | Verdict | Reason |
|---|---|---|
| `FDA-2023-V.B.6` | **MISSING** | The threat describes plaintext credential transmission over BLE, implying a lack of authenticated, encrypted pairing or link security. The existing control explicitly states 'no network encryption for credentials' and does not address wireless pairing mechanisms. |
| `FDA-2023-V.B.4` | **MISSING** | The threat explicitly states that credentials are transmitted in plaintext over TCP or BLE, directly violating the requirement for confidentiality during transmission. The existing control confirms 'no network encryption for credentials'. |
| `FDA-2023-V.B.2` | **MISSING** | Neither the threat description nor the existing control provides any information regarding the implementation of role-based authorization, principle of least privilege, or separation of administrative functions. |
| `FDA-2023-V.B.9` | **MISSING** | The threat focuses on network transmission, and the existing control, while mentioning 'physical protection only', explicitly clarifies 'no network encryption for credentials', which does not address the hardening of physical ports or debug interfaces. |
| `FDA-2023-V.B.1` | **MISSING** | The threat explicitly states the use of 'Default "service/service" credentials', which is directly prohibited by this clause. The existing control does not address authentication mechanisms or credential policies. |
| `FDA-2023-V.B.5` | **MISSING** | The threat describes plaintext transmission of credentials over TCP and BLE. The existing control explicitly states 'no network encryption for credentials', indicating a complete absence of transport-layer encryption like TLS 1.2+. |

**Proposed controls:**
- `CTRL:PROPOSED:tls-encryption` — Implement TLS 1.2+ for all network communications to ensure encryption of credentials.
- `CTRL:PROPOSED:ble-secure-connections` — Use BLE LE Secure Connections with numeric comparison or out-of-band authentication for pairing.
- `CTRL:PROPOSED:remove-default-credentials` — Remove default 'service/service' credentials and enforce strong, unique credentials.

**Proposed doc changes:**
- SRS.md · **add** `SRS-SEC-NEW-01` — All network communications must use TLS 1.2 or later with mutual authentication and certificate pinning.
- SRS.md · **add** `SRS-SEC-NEW-02` — Bluetooth Low Energy connections must use LE Secure Connections with numeric comparison or out-of-band authentication.
- SRS.md · **add** `SRS-SEC-NEW-03` — Default credentials must be removed and replaced with strong, unique credentials for each deployment.

**Proposed code changes:**

`firmware/network_security.c:0` (create_file)
```
void setup_tls() {
    // Implement TLS 1.2+ setup here
}

```
`firmware/ble_security.c:0` (create_file)
```
void setup_ble_secure_connections() {
    // Implement BLE LE Secure Connections setup here
}

```
`firmware/credentials.c:0` (create_file)
```
void remove_default_credentials() {
    // Remove default 'service/service' credentials
}

```

---

## P-LOG-T · Log Buffer Corruption
**STRIDE:** T   **CVSS:** 7.6 High   **Priority:** P1   **Effort:** 2 eng-weeks
**Residual risk:** Medium — Implementing secure boot and JTAG protection reduces risk, but residual risk remains due to potential new attack vectors.

The threat of log buffer corruption via JTAG exploitation is critical. Existing CRC-32 checks are insufficient. Proposed controls include implementing secure boot, disabling or securing JTAG, and upgrading log integrity checks to SHA-256.

**Existing controls (legacy):**
- `CTRL:crc-32-checksum-on-log-sectors` — CRC-32 checksum on log sectors

**Gap analysis:**

| Clause | Verdict | Reason |
|---|---|---|
| `FDA-2023-V.B.9` | **MISSING** | The threat explicitly states JTAG could be exploited, indicating debug interfaces are not disabled or protected. No existing control addresses the hardening of physical ports or debug interfaces as required by this clause. |
| `FDA-2023-V.B.8` | **PARTIAL** | The 'CRC-32 checksum on log sectors' (CTRL:crc-32-checksum-on-log-sectors) provides some tamper-evidence for logs. However, CRC-32 is not considered a strong cryptographic integrity check and does not meet the modern bar for 'tamper-evident properties' against a determined attacker exploiting JTAG. |
| `NIST-800-193-5.2` | **PARTIAL** | The 'CRC-32 checksum on log sectors' (CTRL:crc-32-checksum-on-log-sectors) detects corruption of log data. While this addresses integrity detection for critical platform data, CRC-32 is not a robust cryptographic integrity mechanism and is insufficient against a JTAG-enabled attacker. |
| `FDA-2023-V.B.7` | **MISSING** | No existing control addresses the implementation of a secure boot chain or runtime integrity monitoring of critical safety code. The listed control only pertains to log data integrity. |
| `NIST-800-193-4.3` | **MISSING** | No existing control describes a Root of Trust for Update (RTU) or mechanisms to protect it. The listed control is for log data integrity, not firmware update authentication components. |
| `NIST-800-193-4.2` | **MISSING** | No existing control addresses the authentication of firmware updates using digital signatures or rollback protection. The listed control is for log data integrity, not firmware update mechanisms. |

**Proposed controls:**
- `CTRL:PROPOSED:secure-boot` — Implement secure boot to ensure only cryptographically verified firmware executes.
- `CTRL:PROPOSED:jtag-protection` — Disable JTAG in production or protect it with strong authentication and audit logging.
- `CTRL:PROPOSED:strong-log-integrity` — Use SHA-256 for log integrity checks to replace CRC-32.

**Proposed doc changes:**
- SDS.md · **add** `SDS-SEC-NEW-01` — Implement secure boot to ensure only cryptographically verified firmware executes after power-on.
- SDS.md · **add** `SDS-SEC-NEW-02` — Disable JTAG in production or protect it with strong authentication and audit logging.
- SDS.md · **add** `SDS-SEC-NEW-03` — Use SHA-256 for log integrity checks to replace CRC-32.

**Proposed code changes:**

`firmware/app_mcu/emr/hl7_formatter.c:102` (modify)
```
// Replace CRC-32 with SHA-256 for log integrity
#include <sha256.h>
// Existing code...
sha256(log_data, log_size, log_hash);
```

---

## P-NET-D · Wi-Fi/Ethernet Flooding via Unfiltered Sockets
**STRIDE:** D   **CVSS:** 7.5 High   **Priority:** P1   **Effort:** 2 eng-weeks
**Residual risk:** Medium — Implementing rate limiting and firewall rules will reduce the risk of network flooding attacks.

The PMx-100 is vulnerable to network flooding attacks due to the lack of rate limiting and firewall protections. Implementing these controls will mitigate the risk of denial-of-service attacks, enhancing the device's network resilience.

**Gap analysis:**

| Clause | Verdict | Reason |
|---|---|---|
| `FDA-2023-V.B.9` | **MISSING** | No controls are listed that address the hardening or protection of physical ports and debug interfaces as required by this clause. The threat is network-based, not related to physical access. |
| `NIST-800-193-5.2` | **MISSING** | No controls are listed that implement detection mechanisms for firmware code, firmware data, or critical platform configuration corruption. The threat is a network-based DoS, not directly related to platform integrity detection. |
| `AAMI-TIR57-7.1` | **MISSING** | No post-market process is described or linked to the device that monitors emerging vulnerabilities, assesses applicability, or communicates mitigations as required by this clause. |
| `FDA-2023-V.B.3` | **MISSING** | No controls are listed that implement cryptographic authenticity verification for firmware images or update artifacts using modern asymmetric cryptography, as required by this clause. |
| `FDA-2023-V.A.1` | **MISSING** | No Secure Product Development Framework (SPDF) is documented or evidenced to integrate cybersecurity considerations throughout the product lifecycle, including threat modeling and secure design, as required. |
| `FDA-2023-V.B.5` | **MISSING** | No controls are listed that implement transport-layer encryption (TLS 1.2 or later) with mutual authentication, certificate validation, or hostname verification for network communications. |

**Proposed controls:**
- `CTRL:PROPOSED:rate-limiting` — Implement rate limiting on incoming ICMP, UDP, and TCP packets to prevent network flooding.
- `CTRL:PROPOSED:firewall` — Deploy a firewall to filter and block unauthorized network traffic.

**Proposed doc changes:**
- SDS.md · **add** `SDS-SEC-NEW-01` — Introduce rate limiting and firewall configurations to mitigate network flooding threats.

**Proposed code changes:**

`firmware/network_security.c:0` (create_file)
```
// Implement rate limiting and firewall rules
void configure_network_security() {
    // Rate limiting logic
    // Firewall rule setup
}

```

---

## P-NET-E · Local Privilege Escalation via JTAG
**STRIDE:** E   **CVSS:** 7.6 High   **Priority:** P1   **Effort:** 1 eng-weeks
**Residual risk:** Medium — JTAG interface remains a potential attack vector despite physical controls.

The JTAG interface poses a significant security risk as it allows attackers with physical access to bypass network security controls. Disabling the JTAG interface in production firmware will mitigate this risk.

**Existing controls (legacy):**
- `CTRL:physical-access-control-lockable-enclosure` — Physical access control (lockable enclosure)

**Proposed controls:**
- `CTRL:PROPOSED:jtag-disable` — Disable JTAG interface in production firmware.

**Proposed doc changes:**
- SDS.md · **add** `SDS-SEC-NEW-01` — Ensure JTAG interface is disabled in production firmware to prevent unauthorized access.

**Proposed code changes:**

`firmware/jtag_control.c:0` (create_file)
```
// Disable JTAG interface in production
void disable_jtag() {
    // Implementation to disable JTAG
}

```

---

## P-NET-S · Wi-Fi/Ethernet MAC Address Spoofing
**STRIDE:** S   **CVSS:** 8.1 High   **Priority:** P1   **Effort:** 2 eng-weeks
**Residual risk:** Medium — Implementing MAC address binding and encrypted wireless links reduces spoofing risk.

The PMx-100 is vulnerable to MAC address spoofing, allowing attackers to impersonate the device. Implementing MAC address binding and securing wireless links with WPA2-Enterprise will mitigate this risk.

**Gap analysis:**

| Clause | Verdict | Reason |
|---|---|---|
| `FDA-2023-V.B.9` | **MISSING** | No existing controls address the requirement for hardening debug interfaces against unauthorized access. |
| `FDA-2023-V.B.6` | **MISSING** | No existing controls ensure that wireless links are secured with authenticated and encrypted mechanisms. |
| `NIST-800-193-5.2` | **MISSING** | No existing controls provide mechanisms for detecting firmware corruption or integrity verification. |
| `FDA-2023-V.B.8` | **MISSING** | No existing controls address the logging of security-relevant events or their tamper-evident properties. |
| `FDA-2023-V.A.1` | **MISSING** | No existing controls indicate the presence of a documented Secure Product Development Framework. |
| `FDA-2023-V.B.3` | **MISSING** | No existing controls provide cryptographic authenticity verification for firmware or update mechanisms. |

**Proposed controls:**
- `CTRL:PROPOSED:mac_binding` — Implement MAC address binding in WPA2-Enterprise to prevent spoofing.
- `CTRL:PROPOSED:encrypted_links` — Ensure all wireless links use WPA2-Enterprise with AES-256 encryption.

**Proposed doc changes:**
- SDS.md · **add** `SDS-SEC-NEW-01` — Implement MAC address binding and enforce WPA2-Enterprise with AES-256 encryption for all wireless communications.

**Proposed code changes:**

`firmware/network_security.c:0` (create_file)
```
// Implement MAC address binding and WPA2-Enterprise with AES-256 encryption
void configure_network_security() {
    // Code to bind MAC address
    // Code to enforce WPA2-Enterprise
}
```

---

## P-SVC-E · Default Credential Exploitation
**STRIDE:** E   **CVSS:** 9.8 Critical   **Priority:** P0   **Effort:** 1 eng-weeks
**Residual risk:** Low — Implementing unique credentials per device will mitigate the risk of default credential exploitation.

The threat of default credential exploitation is critical due to the use of hardcoded credentials that allow full access to the service menu. To mitigate this, we propose implementing unique credentials for each device, which will significantly reduce the risk of unauthorized access.

**Existing controls (legacy):**
- `CTRL:default-credentials-stored-in-plaintext-json` — Default credentials stored in plaintext JSON

**Proposed controls:**
- `CTRL:PROPOSED:unique-device-credentials` — Implement unique credentials for each device to replace default credentials.

**Proposed doc changes:**
- SRS.md · **add** `SRS-SEC-NEW-01` — Each device must be provisioned with unique credentials to prevent unauthorized access through default credentials.

**Proposed code changes:**

`firmware/authentication.c:0` (create_file)
```
// Implement unique credential generation and storage
void generate_unique_credentials() {
    // Code to generate and securely store unique credentials
}

```

---

## P-WDT-E · Exploit Watchdog to Bypass Safety Checks
**STRIDE:** E   **CVSS:** 7.6 High   **Priority:** P0   **Effort:** 4 eng-weeks
**Residual risk:** Medium — Implementing secure boot and cryptographic verification reduces risk but does not eliminate physical tampering threats.

The threat of exploiting the watchdog to bypass safety checks is critical due to missing secure boot and integrity verification controls. Implementing secure boot, runtime integrity monitoring, and hardening debug interfaces will significantly reduce the risk of unauthorized firmware execution.

**Existing controls (legacy):**
- `CTRL:physical-protection-only-no-cryptographic-signatures` — Physical protection only (no cryptographic signatures)

**Gap analysis:**

| Clause | Verdict | Reason |
|---|---|---|
| `FDA-2023-V.B.7` | **MISSING** | No existing control addresses secure boot or cryptographic verification of firmware. |
| `FDA-2023-V.B.9` | **MISSING** | No existing control addresses the protection of debug interfaces or service ports. |
| `NIST-800-193-5.2` | **MISSING** | No existing control provides for detection of firmware corruption or integrity verification. |
| `NIST-800-193-4.2` | **MISSING** | No existing control addresses firmware update authentication or digital signature verification. |
| `NIST-800-193-4.3` | **MISSING** | No existing control provides for a Root of Trust for firmware updates. |
| `FDA-2023-V.B.3` | **MISSING** | Existing control does not provide cryptographic integrity verification for firmware updates. |

**Proposed controls:**
- `CTRL:PROPOSED:secure-boot` — Implement secure boot to ensure only cryptographically verified firmware executes.
- `CTRL:PROPOSED:firmware-integrity-monitoring` — Add runtime integrity monitoring to detect unauthorized firmware modifications.
- `CTRL:PROPOSED:debug-interface-hardening` — Disable or protect debug interfaces and service ports with strong authentication.
- `CTRL:PROPOSED:firmware-update-authentication` — Authenticate firmware updates using digital signatures verified against a trusted key store.
- `CTRL:PROPOSED:root-of-trust` — Establish a Root of Trust for Update to authenticate firmware updates.

**Proposed doc changes:**
- SRS.md · **add** `SRS-SEC-NEW-01` — The system shall implement a secure boot process ensuring only cryptographically verified firmware is executed.
- SDS.md · **add** `SDS-SEC-NEW-01` — Runtime integrity monitoring shall be implemented to detect and respond to unauthorized firmware modifications.

**Proposed code changes:**

`firmware/bootloader.c:0` (create_file)
```
// Implement secure boot process
void secure_boot() {
    // Verify firmware signature
    // Load verified firmware
}
```
`firmware/integrity_monitor.c:0` (create_file)
```
// Implement runtime integrity monitoring
void monitor_firmware_integrity() {
    // Periodically check firmware integrity
    // Report any unauthorized modifications
}
```

---

## P-WDT-T · Safety MCU Watchdog Bypass
**STRIDE:** T   **CVSS:** 7.3 High   **Priority:** P2   **Effort:** 2 eng-weeks
**Residual risk:** Medium — Physical tampering risk reduced but not eliminated with proposed controls.

The Safety MCU watchdog can be bypassed through physical tampering, allowing the App MCU to run unchecked. To mitigate this, we propose implementing secure boot, runtime integrity monitoring, and firmware update authentication. These measures will significantly reduce the risk of unauthorized firmware execution and modification.

**Existing controls (legacy):**
- `CTRL:physical-protection-via-tamper-evident-seals` — Physical protection via tamper-evident seals

**Gap analysis:**

| Clause | Verdict | Reason |
|---|---|---|
| `FDA-2023-V.B.9` | **MISSING** | No existing control addresses the requirement for disabling or protecting debug interfaces against unauthorized access. |
| `FDA-2023-V.B.7` | **MISSING** | No existing control addresses the need for a secure boot chain or runtime integrity monitoring. |
| `NIST-800-193-5.2` | **MISSING** | No existing control addresses the requirement for detecting corruption of firmware or platform configuration. |
| `NIST-800-193-4.3` | **MISSING** | No existing control addresses the need for a Root of Trust for Update. |
| `NIST-800-193-4.2` | **MISSING** | No existing control addresses the requirement for authenticating firmware updates with a digital signature. |
| `FDA-2023-V.B.3` | **MISSING** | No existing control addresses the requirement for cryptographic authenticity verification of firmware and updates. |

**Proposed controls:**
- `CTRL:PROPOSED:secure-boot` — Implement secure boot to ensure only verified firmware executes.
- `CTRL:PROPOSED:runtime-integrity` — Add runtime integrity monitoring for critical safety code.
- `CTRL:PROPOSED:firmware-authentication` — Authenticate firmware updates using digital signatures.

**Proposed doc changes:**
- SRS.md · **add** `SRS-SEC-NEW-01` — The device shall implement a secure boot chain to ensure only cryptographically verified firmware may execute after power-on.
- SRS.md · **add** `SRS-SEC-NEW-02` — The device shall include runtime integrity monitoring to detect and respond to unauthorized modification of critical safety code.
- SRS.md · **add** `SRS-SEC-NEW-03` — All firmware updates shall be authenticated by verifying a digital signature over the update image using a public key rooted in a trusted key store.

**Proposed code changes:**

`firmware/bootloader.c:0` (create_file)
```
// Implement secure boot logic
void secure_boot() {
    // Verify firmware signature
    // Boot verified firmware
}
```
`firmware/integrity_monitor.c:0` (create_file)
```
// Implement runtime integrity monitoring
void monitor_integrity() {
    // Check integrity of critical safety code
    // Alert on unauthorized modifications
}
```

