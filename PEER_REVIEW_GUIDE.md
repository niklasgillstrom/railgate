# Peer-review guide — railgate

This document is written for a peer reviewer of Article 1 (Gillström, in preparation; target venue: *Capital Markets Law Journal*) and Article 2 (Gillström, in preparation; target venue: *Computer Law & Security Review*) who wants to reproduce the central settlement-layer-enforcement claims those articles make. The companion repos `hsm/` and `gatekeeper/` complete the **triadic system** (since v1.2.0) described in Article 1 §4.2 and §4.3 and in Article 2 §6.1 and §9.3:

- **hsm** carries the verifier core (financial-entity side).
- **gatekeeper** is the NCA-operated supervisory API; from v1.1.0 also exposes the settlement-time signature verification endpoint that railgate consumes.
- **railgate** (this repo) is the central-bank settlement-rail enforcement layer that calls gatekeeper's verification endpoint at settlement time (RIX-INST in Sweden; generalisable to TIPS, FedNow, FPS, NPP).

The three components together operationalise the data-minimised quadruple-triangulation model: only digest, signature, and certificate identifiers traverse the supervisor boundary — no transaction payload content is exposed at any layer.

---

## What this repo is / isn't

**Is:**

- A **reference implementation** of settlement-rail enforcement as described in Article 1 §4.3 and §6.2 and in Article 2 §6.1 and §9.3. Railgate sits at the central-bank settlement rail and performs deterministic cryptographic signature verification at settlement time, blocking any settlement that cannot be matched to a compliant gatekeeper audit entry.
- A **demonstration** of the data-minimisation contract: the supervisor never sees transaction payload content, only the SHA-512 digest, the signature, and the certificate identifiers. SHA-512 collision resistance binds the signature to the payload the digest was taken over — not, by itself, to the pacs.008 message being settled; see the note on the residual binding assumption in `README.md`.
- A **default-deny enforcement** prototype with structured reason codes (`ALLOWED`, `DORA_32_AUDIT_MISSING`, `SIGNATURE_INVALID`, `CERT_NON_COMPLIANT`, `NETWORK_ERROR`, etc.) returned to the originating bank.

**Isn't:**

- A production-ready integration with Sveriges Riksbank's RIX-INST or any other central-bank settlement system. Production deployment requires substituting the in-memory `PaymentNetworkClient` for an HTTP-based client against the actual payment-network operator's signature-retrieval endpoint, configuring the gatekeeper URL for the supervisor's instance, and integrating with the central bank's pacs.008 processing pipeline. None of those integration points is part of this repo.
- An ISO 20022 parser. The `SettlementRequest` model abstracts the fields railgate needs (`transactionReference`, `localInstrumentCode`, debtor/creditor identification flags, BICs); a production deployment would receive the full pacs.008 message and parse the relevant fields. The abstraction here keeps the reference focused on the verification orchestration logic.

---

## Version 1.3.0 — what changed and what to verify

A systematic check of the triad against its own documentation found places where a described protection was not implemented in the code. In summary:

- `GatekeeperClient` had no connect or read timeout, so an unresponsive gatekeeper blocked the calling thread instead of producing a deny. Timeouts are now configurable and bounded by default.
- A gatekeeper outage was reported to the originating bank as `SIGNATURE_INVALID`, because the `NETWORK_ERROR` branch was unreachable. Infrastructure failure and cryptographic failure are no longer conflated.
- The audit log copied its entire backing array on every settlement decision; it is now a bounded ring buffer.
- `GatekeeperClient` had no tests at all, which is where every fail-open risk in this repository lives. `GatekeeperClientTest` now drives the real client against a stubbed transport.
- The claim that SHA-512 collision resistance binds the signature to the settled transaction has been corrected throughout: it binds the signature to the payload the digest was taken over. See `README.md` for the residual assumption and what would close it.

Reviewers should start with `mvn -B test` (11 tests).

---

## Version 1.2.0 — what changed and what to verify

Reviewers approaching v1.2.0 should focus on the following:

1. **Settlement-time orchestration** (`SettlementOrchestrator`) — verify the flow: regulated-payment detection → payment-network signature retrieval → gatekeeper verification → allow/default-deny.
2. **Regulated-payment detection** (`RegulatedPaymentDetector`) — both paths must work: explicit `LclInstrm/Cd` matching (e.g. "SWISH"), and structural derivation (`OrgId(debtor)` + `PrvtId(creditor)` = organisation-to-private = Swish utbetalning). The structural path cannot be circumvented by the originating bank — the directional structure is inherent to the transaction.
3. **Data-minimisation contract** — the JSON wire format for `SettlementRequest`, `PaymentSignature`, and the gatekeeper-bound `SignatureVerificationRequest` must contain only digest, signature, and certificate identifiers. There must be no payload field. `GatekeeperClientTest.forwardsExactlyTheFourDataMinimisedFields` asserts this against the real outbound request body, including a field count so that a fifth field cannot be added without the test failing.
4. **Default-deny logic** — the orchestrator returns `allow = false` whenever (a) the payment-network operator has no record of the transaction, (b) the gatekeeper rejects the signature, (c) the gatekeeper marks the certificate non-compliant, or (d) the gatekeeper is unreachable. Paths (a)-(c) are covered by `SettlementOrchestratorTest`; path (d) is covered by `GatekeeperClientTest`, which drives the real client against a stubbed transport (server error, empty body, unparseable body, foreign JSON) and asserts a deny in every case. Note that a gatekeeper outage is reported as `NETWORK_ERROR`, not `SIGNATURE_INVALID` — the two must not be conflated, since the latter is an accusation against the originating bank.

---

## Requirements

- **Java 21** (Spring Boot 4.x baseline)
- **Maven 3.6.3** or later (enforced by `maven-enforcer-plugin`)
- Access to a running gatekeeper instance for end-to-end testing (defaults to `http://localhost:8080`); the unit tests substitute a mocked `GatekeeperClient` so a live gatekeeper is not required for `mvn -B test`.

---

## Build and test

```bash
mvn -B clean verify
```

Expected output:

```
[INFO] Tests run: 6, Failures: 0, Errors: 0, Skipped: 0
[INFO] BUILD SUCCESS
```

The 6 tests in `SettlementOrchestratorTest` exercise:

1. `allowsSettlementWhenSignatureVerifiesAndCertCompliant` — happy path; gatekeeper returns `signatureValid=true, compliant=true`.
2. `deniesWhenSignatureMissingFromPaymentNetwork` — payment-network operator has no record → `DORA_32_AUDIT_MISSING`.
3. `deniesWhenSignatureInvalid` — gatekeeper returns `signatureValid=false` → `SIGNATURE_INVALID`.
4. `deniesWhenCertNonCompliant` — gatekeeper returns `compliant=false` → `CERT_NON_COMPLIANT`.
5. `identifiesSwishUtbetalningByStructuralDerivation` — `OrgId` + `PrvtId` flags trigger regulated-payment detection without explicit `LclInstrm` code.
6. `passesThroughNonRegulatedSettlements` — non-regulated settlements are not subject to railgate enforcement (returns `allow=true, NOT_REGULATED`).

OWASP Dependency-Check runs as part of `verify`; it currently flags an informational DOMPurify finding inside swagger-ui that is documented and suppressed in `.owasp-suppressions.xml`.

---

## Reproducible assertions

The following assertions are reproducible by running `mvn -B test`:

- The orchestrator's data-minimisation contract holds for the JSON wire format. (Test 1 + 4 — neither request nor response contains a transaction payload field.)
- Default-deny returns the correct structured reason code for each failure mode. (Tests 2, 3, 4.)
- Structural derivation identifies regulated payments without bank-supplied metadata. (Test 5.)
- Non-regulated settlements are passed through without verification. (Test 6.)

---

## Configuration knobs

| Property | Default | Purpose |
|---|---|---|
| `railgate.payment-network.mode` | `in-memory` | Selects the `PaymentNetworkClient` implementation. The in-memory implementation is used by `mvn -B test` and by the reference demonstration flow. Production deployments substitute an HTTP-based client. |
| `railgate.gatekeeper.base-url` | `http://localhost:8080` | URL of the supervisor's gatekeeper instance. |
| `railgate.regulated.local-instrument-codes` | `SWISH` | Comma-separated list of `LclInstrm/Cd` values that identify regulated payments. |

---

## Known limitations and their scope

### `InMemoryPaymentNetworkClient` is not a real payment-network operator (Critical for production)

The reference implementation registers signature artefacts in an in-memory map. A production deployment must implement an HTTP-based client against Getswish AB's signature-retrieval endpoint (or the equivalent for other jurisdictions) and replace the in-memory adapter via the `railgate.payment-network.mode` property.

### `SettlementRequest` is an abstraction, not a pacs.008 parser (High for production)

The reference accepts a Java DTO with the four fields railgate actually needs. A production integration with RIX-INST would receive the full pacs.008 message via SWIFT or the central-bank API and parse the relevant fields (`PmtTpInf/LclInstrm`, `Dbtr/Id`, `Cdtr/Id`, `RmtInf` etc.) before calling the orchestrator.

### Regulatory deployment integration is the central-bank's responsibility (Inherent)

Railgate is operated by the central-bank settlement-rail operator (Sveriges Riksbank for RIX-INST), not by the supervisor (FI). The reference implementation does not attempt to model the deployment integration with a specific central bank; the central bank's IT and operational teams own that work. What this repo demonstrates is that the architecture is implementable using public standards (ISO 20022, RSA-PKCS#1 v1.5 + SHA-512) and existing supervisory mandates (DORA Art 32 oversight forum).

---

## Regulatory mapping

| DORA provision | What railgate addresses |
|---|---|
| Art 6.4 / 6.6 (operational separation) | Settlement-rail enforcement is structurally separate from the certificate-issuing bank, providing the external-actor link required by structural-independence analysis. |
| Art 6.10 (verification of compliance) | Per-settlement verification at the rail makes the verification continuous, complementing the one-time attestation verification at issuance. |
| Art 9 (ICT security) | Cryptographic signature verification (RSA-PKCS#1 v1.5 + SHA-512) of every regulated payment. |
| Art 28.4(e) (intra-group arrangements) | Default-deny prevents settlement of payments whose certificates were not issued through the structurally compliant gatekeeper flow. |
| Art 32 (oversight forum) | Provides the formal coordination basis between supervisor (gatekeeper-operator) and central bank (railgate-operator). |
| Art 35–42 (supervisory powers) | Audit-log of railgate decisions supports the supervisory record. |

| GDPR provision | What railgate addresses |
|---|---|
| Art 5(1)(c) (data minimisation) | The supervisor's verification chain receives only digest, signature, and certificate identifiers — never transaction payload content. SHA-512 collision resistance binds the digest to the signed payload; binding it to the settled message would require the rail to carry the signed fields (see `README.md`). |

---

## How to extend

For a production deployment, the following extension points must be addressed:

1. **`PaymentNetworkClient` HTTP implementation** — replace `InMemoryPaymentNetworkClient` with an HTTP client that calls Getswish AB's (or equivalent's) signature-retrieval endpoint. Set `railgate.payment-network.mode` to a non-default value and provide a Spring bean that implements `PaymentNetworkClient`.
2. **pacs.008 ingress** — wire the `SettlementController.precheck` endpoint into the central-bank settlement pipeline. The pipeline must extract the four fields needed by `SettlementRequest` from the incoming pacs.008 and synchronously block the settlement based on the orchestrator's response.
3. **mTLS configuration** — production deployments require mTLS between railgate and the supervisor's gatekeeper instance. The `SETTLEMENT_RAIL` role on the gatekeeper side authorises railgate to call `/api/v1/verify`.
4. **Persistent audit log** — the `RailgateAuditLog` reference uses an in-memory list. Production deployments must back this with a tamper-evident persistent log (a hash-chained append-only file in the manner of `AppendOnlyFileAuditLog` in the gatekeeper repo would be a suitable starting point).

---

## How to cite

See `CITATION.cff`. When citing, please cite all three companion artefacts together where appropriate (hsm, gatekeeper, railgate).
