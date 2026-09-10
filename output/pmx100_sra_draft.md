# Security Risk Assessment — draft

One entry per threat. Each entry carries CVSS v3.1 scoring, gap analysis against FDA / IEC / AAMI / NIST, and proposed doc + code changes.

---

## DF-BLEPAIR-I · Unencrypted BLE Pairing Traffic Capture
**STRIDE:** I   **CVSS:** 8.1 High   **Priority:** P1   **Effort:** 1.5 eng-weeks
**Residual risk:** Medium — Implementing LE Secure Connections will mitigate the threat, but residual risk remains due to potential implementation flaws.

The current BLE pairing process is vulnerable to interception due to lack of encryption, allowing adversaries to capture sensitive keys. Implementing BLE LE Secure Connections will encrypt pairing traffic, significantly reducing the risk of key exposure.

**Existing controls (legacy):**
- `CTRL:tls-1-0-for-encrypted-data-in-transit-legacy` — TLS 1.0 for encrypted data-in-transit (legacy)

**Gap analysis:**

| Clause | Verdict | Reason |
|---|---|---|
| `FDA-2023-V.B.6` | **MISSING** | The threat describes unencrypted BLE pairing in Just Works mode, which the clause explicitly prohibits and requires LE Secure Connections. The existing TLS 1.0 control does not address BLE pairing security. |
| `FDA-2023-V.B.9` | **MISSING** | The clause addresses physical port and debug interface hardening, which is unrelated to the BLE pairing threat or the existing TLS 1.0 control. |
| `FDA-2023-V.B.5` | **PARTIAL** | The existing control uses TLS 1.0 for data-in-transit, which is a form of transport-layer encryption. However, the clause explicitly requires TLS 1.2 or later, making TLS 1.0 a partial fulfillment. |
| `FDA-2023-V.B.4` | **PARTIAL** | The existing control uses TLS 1.0 for data-in-transit, providing some confidentiality. However, TLS 1.0 is not a 'current, standards-based algorithm' as required, and the threat specifically notes unencrypted BLE pairing traffic, which is not covered. |
| `FDA-2023-V.B.8` | **MISSING** | The clause addresses audit logging and event traceability, which is unrelated to the BLE pairing threat or the existing TLS 1.0 control. |

**Proposed controls:**
- `CTRL:PROPOSED:ble-le-secure-connections` — Implement BLE LE Secure Connections with numeric comparison or out-of-band authentication for pairing.

**Proposed doc changes:**
- SRS.md · **add** `SRS-SEC-NEW-01` — The system shall use BLE LE Secure Connections with numeric comparison or out-of-band authentication for all pairing processes to ensure encrypted and authenticated communication.

**Proposed code changes:**

`firmware/ble_pairing.c:0` (create_file)
```
// Implement BLE LE Secure Connections
#include <ble_secure_connections.h>

void setup_ble_pairing() {
    ble_secure_connections_init();
    ble_secure_connections_set_authentication_mode(NUMERIC_COMPARISON);
}

```

