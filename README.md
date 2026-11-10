# railgate — Settlement-layer enforcement reference for DORA-compliant payment infrastructure

Reference implementation of the settlement-rail enforcement component
described in the companion academic article. railgate sits at the
central-bank settlement rail (RIX-INST in the Swedish reference
deployment, generalisable to TIPS, FedNow, FPS, NPP, etc.) and performs
deterministic cryptographic signature verification at settlement time.
Companion artefact to **hsm**
([DOI 10.5281/zenodo.19930310](https://doi.org/10.5281/zenodo.19930310))
and **gatekeeper**
([DOI 10.5281/zenodo.19930395](https://doi.org/10.5281/zenodo.19930395)).

## Why three components

The triple **hsm + gatekeeper + railgate** operationalises a
quadruple-triangulation model over four data sources (Article 1 §6.2,
Article 2 §9.3): Getswish AB's allocation register, the gatekeeper audit
log, the RIX-INST settlement log and the recipient-side transaction
registration. Of these the code produces the gatekeeper audit log; the
other three are kept outside these repositories, and railgate's own
decision log and replay record are not the RIX-INST settlement log. Each
component answers one specific question:

| Component  | Question answered                                                            |
|------------|------------------------------------------------------------------------------|
| hsm        | Is the key HSM-bound and on-device generated?                                |
| gatekeeper | Is the certificate-issuance compliant, and does the signature verify?        |
| railgate   | Is settlement permitted, given the gatekeeper response and no circumvention? |

Each component is deployable independently. railgate's role is not
verification (gatekeeper does that). railgate's role is **enforcement at
the chokepoint where verification can no longer be bypassed** — the
central-bank settlement rail.

## Architecture overview

```
[Customer HSM] ─signs digest with private key
       ↓
[Bank Swish-API mottagande]
       ↓
[Bank → Getswish AB API call] ─Getswish stores {digest, signature, certSerial}
       ↓
[Instructing Party → RIX-INST pacs.008, SIP model, on Swish's mandate]
       ↓
[Riksbanken / settlement-layer] ─hands railgate a SettlementRequest derived from the pacs.008
       ↓
   railgate detects regulated payment via:
     • LclInstrm/Cd = "SWISH" (case-insensitive, trimmed), or
     • OrgId(debtor) + PrvtId(creditor) → org → private
       (Swish utbetalning, and refunds of Swish Handel payments)
     • either flag missing → treated as regulated
       ↓
   railgate → payment-network operator: lookup(transactionReference)
     (http mode: GET /v1/payout-artefacts/{ref}, answer signed op1,
      verified under railgate.payment-network.trusted-keys)
       ↓
   railgate reserves the reference and payoutInstructionId
     (already allowed or in flight → REFERENCE_ALREADY_SETTLED)
       ↓
   railgate → gatekeeper.verify(certSerial, issuerDn, digest, signature)
       ↓
   gatekeeper (1.5.0 or later):
     1. Look up cert stored at Step 7 via (certSerial, issuerDn)
     2. Signature.getInstance("SHA512withRSA")
          .initVerify(publicKey); update(digest); verify(signature)
     3. Check compliance and lifecycle status of the registry entry
     4. Return {signatureValid, compliant, reason, ...}
     5. (1.7.0 or later) Sign the verdict over sv1
       ↓
   railgate verifies the verdict signature (1.7.0) under
     railgate.gatekeeper.trusted-keys and its freshness
       ↓
   railgate decides: allow ↔ default-deny (block settlement)
     allow → reference and payoutInstructionId committed (replay record)
     deny  → both released
       ↓
[Audit log entry recorded]
```

**Gatekeeper version.** Step 1 of the gatekeeper box is true from
gatekeeper 1.5.0, which stores the issued certificate at Step 7
confirmation and looks it up by `(certSerial, issuerDn)`. Up to and
including gatekeeper 1.4.0 it did not exist: `POST /api/v1/verify` required
a `signingCertificatePem` that railgate never sends, answered every
railgate request with `MALFORMED_INPUT`, and railgate reported that to the
originating bank as `SIGNATURE_INVALID`. Every regulated settlement was
denied. railgate 1.5.0 requires gatekeeper 1.5.0 or later. Step 5 exists
from gatekeeper 1.7.0, and railgate 1.7.0 requires it by default
(`railgate.gatekeeper.require-signed-verdict=true`): against an older
gatekeeper every settlement that reaches it is denied with
`VERDICT_SIGNATURE_INVALID`.

**Wire contract.** railgate sends exactly four JSON properties, which are
the required fields of gatekeeper's `SignatureVerificationRequest`:

| Property          | Format                                                                 | Gatekeeper limit        |
|-------------------|------------------------------------------------------------------------|-------------------------|
| `certSerial`      | Hexadecimal, case-insensitive, optional `0x` prefix. Compared numerically (`BigInteger`), so `0x00C0FFEE` and `c0ffee` are the same serial. Not decimal. | `@NotBlank`, `@Size(max = 128)` |
| `issuerDn`        | RFC 4514 string, e.g. `CN=Example CA,O=Example Bank,C=SE`. Compared by `X500Principal` equality. | `@NotBlank`, `@Size(max = 512)` |
| `digestHex`       | SHA-512, exactly 128 hexadecimal characters.                           | `@NotBlank`, `@Size(max = 256)` |
| `signatureBase64` | Standard base64.                                                       | `@NotBlank`, `@Size(max = 4096)` |

`signingCertificatePem` and `algorithm` are never sent, and neither is the
operator's `payoutInstructionId`. `GatekeeperClient`
checks every row before the call and answers `INVALID_SIGNATURE_MATERIAL`
without calling the gatekeeper when one fails, so a request the gatekeeper
would reject with a 400 does not become a `NETWORK_ERROR`. If no stored
certificate matches, the gatekeeper answers `CERT_NOT_FOUND`, which railgate
passes through. The contract is pinned by
`GatekeeperClientTest.requestBodyMatchesTheGatekeeperSignatureVerificationRequest`
and the size-limit tests beside it. A payment-network operator that stores
the serial in decimal must convert it before it reaches railgate: a string
of decimal digits is also valid hexadecimal and names a different
certificate, which the gatekeeper will report as `CERT_NOT_FOUND`.

**What regulated-payment detection rests on.** Both party-type flags are
metadata. The settlement system derives them from `Dbtr/Id/OrgId` and
`Cdtr/Id/PrvtId` and hands them to railgate in `SettlementRequest`;
railgate does not receive the pacs.008, does not parse it, and cannot
recompute the derivation. Earlier versions of this documentation said the
structural path "cannot be circumvented by the originating bank". That
overstates what the code does. What holds is narrower: the structural path
is harder to suppress than the instrument code, because a payout has to
identify its creditor as a private person somewhere in the message for the
payment to reach one; both flags are mandatory, so omitting one is a 400
rather than a pass-through; and a request that reaches the detector without
them is treated as regulated. An absent classification produces
verification, never an allow.

**Who writes the pacs.008.** Swish payments are settled in RIX-INST under
the SIP model: one Instructing Party, approved by the Riksbank, acts for
both the sending and the receiving participant, and for Swish payments the
mandate is given to it by Swish on the participants' behalf (Anvisningar
RIX-INST, section 14.2.2). The payment can be reconciled before it reaches
RIX-INST, so no amount is reserved and no payment request goes to the
receiving participant. In the pacs.008 for the standard and SIP models
(Anvisningar RIX-INST, section 22.4, Table 64), `PmtTpInf/LclInstrm` is
mandatory, `EndToEndId` and `UETR` are optional, and every field through
`UltmtDbtr/Nm` except `TxId` (used for the duplicate check), the settlement amount's currency and
the acceptance timestamp gets schema validation only. Everything railgate
could use to classify a payment is therefore set on Swish's instruction and
not checked by the Riksbank. The code values Swish puts in `LclInstrm` are
not published there. `railgate.regulated.local-instrument-codes` must hold
a code that only payouts carry: a code that every Swish payment carries
would send private-to-private payments to verification, where they have no
signature artefacts and are denied.

**Refunds of Swish Handel payments are denied (not resolved).** A refund
goes from the merchant, an organisation, to the payer, a private person, so
the structural path classifies it as regulated. In the Swish API a refund
is made with the merchant's TLS client certificate; the signing certificate
is required only for the payout API (stated by the `getswish` client
library's documentation, not checked against Getswish AB's own). A refund
therefore has no signature artefacts at the payment-network operator, and
railgate answers `DORA_32_AUDIT_MISSING`. Whether that happens in
production depends on how refunds are coded in the pacs.008, which is not
established. A refund label in the message would not resolve it: the label
is set on Swish's instruction, so trusting it would move the bypass from
omitting the instrument code to labelling a payout as a refund.

What would resolve it is a reference to the original payment that railgate
checks against the Riksbank's own settlement data. A settlement from
organisation to private person would then be verified as a payout unless
it references a payment settled in RIX-INST in the opposite direction
between the same parties whose amount covers this and every earlier refund
against it. Without the reference, it would be denied. A forged original
would require a real settled transfer between the two banks' RIX-INST
accounts. The RIX-INST rules do not require the reference (Table 64).
DORA does: Getswish AB is a financial entity under DORA since its clearing
authorisation (Finansinspektionen, 29 January 2026, dnr 24-30532), and
Article 9(2) and 9(3)(c) require it to maintain the authenticity and
integrity of data in transit and to prevent their impairment. A refund
label that cannot be checked impairs the authenticity of the payout
instruction it can stand in for. railgate can set the reference as a
condition. It does not yet: `SettlementRequest` carries neither the amount
nor the parties' identities nor a reference to an earlier payment, and
railgate has no access to settled payments.

## Data minimisation

railgate **never** sees, transports, or stores transaction payload
content — no amounts, no account or alias identifiers, no business message.

Two data sets have to be distinguished, because they are not the same set.

**What railgate receives** from the settlement rail, in
`SettlementRequest`:

- the **transaction reference** (pacs.008 EndToEndId or UETR)
- the **local instrument code**, when the originating bank populated it
- the **party-type flags** `debtorIsOrganization` and
  `creditorIsPrivatePerson`, derived by the settlement system from
  `Dbtr/Id/OrgId` and `Cdtr/Id/PrvtId`
- the **debtor and creditor BICs** — the originating and receiving banks
- optionally a **declared certificate serial**

The BICs and the party-type flags identify institutions and party
categories. They are not payload content and they are not personal data
about the payer or payee, but they are more than the digest, and the
earlier version of this section did not list them.

**What railgate forwards to the supervisor's gatekeeper**, which is the
boundary the data-minimisation claim is about:

- the SHA-512 **digest** (a 64-byte cryptographic hash, not the payload)
- the RSA **signature** over that digest
- the certificate **serial number** and issuer DN

Nothing else crosses that boundary. The test
`GatekeeperClientTest.forwardsExactlyTheFourDataMinimisedFields` asserts
that the outbound body carries exactly those four fields. The supervisor
never receives the BICs, the party-type flags, the transaction amounts,
sender or receiver detail, business message content, or any payload
bytes. This satisfies GDPR Art 5(1)(c) data
minimisation and the proportionality requirement implicit in DORA Art 32
supervisory data processing.

railgate's own audit log records the transaction reference, the decision,
the reason code, two gatekeeper references and, since 1.7.0, the status of
the gatekeeper's verdict signature (`verdictSignature`: `VERIFIED`,
`UNSIGNED`, `UNVERIFIED`, `INVALID`, or `null` when no verdict was used) —
not the BICs and not the flags. `gatekeeperAuditEntryId` is the gatekeeper's approval-registry
`verificationId`, shared by every settlement against the same certificate
and `null` on `CERT_NOT_FOUND`; `gatekeeperAuditEntryHashHex` (gatekeeper
1.5.0 and later) is the hash of the gatekeeper's own `SETTLEMENT_VERIFY`
audit entry for the call, which identifies that one decision in the
gatekeeper's hash-chained log. A `VERDICT_*` denial carries neither
reference: railgate discards them from a verdict it did not accept.

**The replay record** *(since 1.7.0)* is a second record at the rail. For
every allowed settlement it keeps the transaction reference and, in `http`
mode, the operator's `payoutInstructionId`; with `railgate.replay.path`
set, each is written to a journal file with the time of the allow, one
line per settlement, kept for good (it is never pruned). It holds no
amounts, parties or payload, but it is a persistent, unbounded list of
every regulated payout reference railgate has allowed, and its retention
needs to be decided like any other record of the rail. No file
permissions are set on it (the process umask applies).

SHA-512 collision resistance ensures that a valid signature over the
digest binds that signature to the payload the digest was taken over.
It does not, on its own, bind the signature to the pacs.008 message
being settled: railgate receives the digest from the payment-network
operator and does not recompute it, because `SettlementRequest` carries
what RIX-INST delivers — a transaction reference, an instrument code and
BICs — and not the amount, currency or counterparty identifiers the
signature was made over. Counterparty identity is in any case resolved
from Swish alias to IBAN by the payment-network operator before
settlement, so the identifier the customer signed is not the identifier
railgate sees.

Two residuals follow, and neither is only an assumption about the
payment-network operator.

The first is substitution. A valid signature over the digest the operator
returns proves that the customer signed *some* payload; railgate cannot
check that it is the payload being settled. If the originating bank
declares a serial in `RgltryRptg`, a different serial from the operator is
denied as `DECLARED_CERT_MISMATCH`; nothing else is cross-checked.

The second is reuse of a transaction reference. railgate looks the
artefacts up by transaction reference. Until 1.6.0 it never recorded a
reference as consumed, so a settlement that carried the reference of an
earlier, genuinely signed payout received that payout's artefacts,
verified, and was allowed — whoever submitted it, including the
originating bank itself. Since 1.7.0 `ReplayGuard` allows each reference,
and each operator `payoutInstructionId`, at most once (see "Replay
protection" below), and keeps the record across restarts when
`railgate.replay.path` is set. What remains: the record is local to one
railgate instance and its journal, not shared across instances; without
`railgate.replay.path` it is lost on restart; and a reference that railgate
allowed but whose settlement then failed downstream cannot be allowed
again, because there is no release. Whether a reference can settle twice
across instances therefore still depends on the settlement rail's own
duplicate detection.

Closing the first requires the settlement message to carry the signed
fields; closing the second fully requires the payment-network operator or
the rail to bind each set of artefacts to a single settlement. Both are
participation conditions for the rail rather than changes to this
artefact: RIX terms are set by the system owner, and ISO 20022 provides
the extension points. railgate implements what is verifiable given what
the rail delivers today.

## Default-deny

When verification cannot be completed, settlement is blocked. The
originating bank receives a structured reason code. This is the complete
set of reason codes railgate can produce — no other value is reachable.
Responses that never reach the settlement logic carry no reason code: 401
from Spring Security for a request without valid HTTP Basic credentials,
413 (`{"error":"request_too_large"}`) from `RequestSizeLimitFilter` for
an oversized body, and 406 for a request whose `Accept` header excludes
`application/json`. A pipeline must treat all three as a deny. *(1.8.0:
until then a request with such an `Accept` header was evaluated, recorded
and, when allowed, entered in the replay record before it was answered 406;
it is now refused before anything is evaluated.)*

| Reason code                | HTTP | allow | Meaning                                                            |
|----------------------------|------|-------|--------------------------------------------------------------------|
| ALLOWED                    | 200  | true  | Signature verified and certificate compliant; settlement proceeds.  |
| NOT_REGULATED              | 200  | true  | Explicitly classified, and not organisation-to-private. Passed through without verification. |
| DORA_32_AUDIT_MISSING      | 403  | false | No signature artefacts found at the payment-network operator (in `http` mode: the operator answered 404). |
| OPERATOR_SIGNATURE_INVALID | 403  | false | `http` mode only *(1.7.0)*: the operator answered 200, but the answer was not accepted — not signed over `op1` by a key in `railgate.payment-network.trusted-keys`, an algorithm outside the allow-list, an answer for another reference, or a body that is not the specified JSON. The gatekeeper was not called. |
| REFERENCE_ALREADY_SETTLED  | 403  | false | *(1.7.0)* The transaction reference, or the operator's `payoutInstructionId`, was already allowed, or another evaluation holds it at this moment; the message says which key and which case. The gatekeeper was not called. |
| DECLARED_CERT_MISMATCH     | 403  | false | The settlement request declares a certificate serial (`declaredCertSerial`, from pacs.008 `RgltryRptg`) that differs numerically from the payment-network operator's, or is not hexadecimal. The gatekeeper was not called. |
| CERT_NOT_FOUND             | 403  | false | Certificate matches no gatekeeper audit entry — issuance was circumvented, or the wrong certificate was used. |
| SIGNATURE_INVALID          | 403  | false | Cryptographic verification failed at the gatekeeper.                |
| CERT_NON_COMPLIANT         | 403  | false | Certificate exists but was not issued through a compliant flow.     |
| CERT_EXPIRED               | 403  | false | The signature verifies, but the certificate is outside its validity period (gatekeeper 1.6.0). |
| CERT_SUPERSEDED            | 403  | false | The signature verifies, but the certificate's key was rotated by a key-lifecycle event at the gatekeeper (gatekeeper 1.7.0). |
| CERT_REVOKED               | 403  | false | The signature verifies, but the certificate's key was revoked by a key-lifecycle event at the gatekeeper (gatekeeper 1.7.0). |
| CERT_DECOMMISSIONED        | 403  | false | The signature verifies, but the certificate's key was decommissioned by a key-lifecycle event at the gatekeeper (gatekeeper 1.7.0). |
| MALFORMED_INPUT            | 403  | false | The gatekeeper could not parse the request. Not a signature failure. |
| ALGORITHM_NOT_SUPPORTED    | 403  | false | The gatekeeper would not run the signature algorithm. Not a signature failure. |
| NETWORK_ERROR              | 403  | false | gatekeeper unreachable, timed out, answering a status other than 2xx *(1.8.0; until then only 4xx and 5xx, and the body of a 3xx answer was read as a verdict)* or more than 65 536 bytes, or returning an unusable body; in `http` mode also the payment-network operator unreachable, timed out, failing TLS, redirecting, or answering any status other than 200 and 404 (the message says which). |
| VERDICT_SIGNATURE_INVALID  | 403  | false | *(1.7.0)* The gatekeeper's verdict was not accepted: unsigned while `railgate.gatekeeper.require-signed-verdict=true`, signature fields incomplete, key not in `railgate.gatekeeper.trusted-keys`, algorithm outside the allow-list, signature not verifying over the request railgate sent, an echoed field differing from it, or an unparseable `verifiedAt`. The gatekeeper was called, but its references are discarded. |
| VERDICT_STALE              | 403  | false | *(1.7.0)* The verdict's signature verifies, but `verifiedAt` is more than `railgate.gatekeeper.verdict-max-skew` from railgate's clock, in either direction. |
| INVALID_SIGNATURE_MATERIAL | 403  | false | The artefacts from the payment-network operator are malformed or outside the wire contract above (digest not 128 hex characters, signature not base64 or over 4096 characters, certificate serial not hexadecimal or over 128 characters, issuer DN not an RFC 4514 name or over 512 characters, any of them blank). The gatekeeper was not called. |
| INVALID_REQUEST            | 400  | false | The settlement request failed Bean Validation — a missing party-type flag, a blank or over-36-character transaction reference, an over-long instrument code, declared certificate serial (128) or BIC (11). No verification was attempted. |
| INTERNAL_ERROR             | 403  | false | Any unhandled failure inside railgate, and *(1.7.0)* an allow that could not be written to the replay journal (the reference is released). Default-deny; no detail about the failure is returned to the caller. |

`CERT_NOT_FOUND`, `CERT_NON_COMPLIANT`, `CERT_EXPIRED`, `CERT_SUPERSEDED`,
`CERT_REVOKED`, `CERT_DECOMMISSIONED`, `SIGNATURE_INVALID`,
`MALFORMED_INPUT` and `ALGORITHM_NOT_SUPPORTED` are read from the
gatekeeper's own `reason` field and passed through unchanged, as are
`NETWORK_ERROR`, `INVALID_SIGNATURE_MATERIAL`, `VERDICT_SIGNATURE_INVALID`
and `VERDICT_STALE`, which railgate's client produces itself. That is every non-positive reason the gatekeeper
documents. Any other `reason` value falls back to a derivation from the two
booleans, which yields `SIGNATURE_INVALID` when the signature did not
verify and `CERT_NON_COMPLIANT` otherwise.

Up to railgate 1.4.0, `MALFORMED_INPUT` and `ALGORITHM_NOT_SUPPORTED` were
not in the pass-through set and reached the originating bank as
`SIGNATURE_INVALID`. Against gatekeeper 1.4.0 that was every regulated
settlement: see *Gatekeeper version* above.

The bank may resubmit the settlement with valid data. In the absence of
valid data, the transaction does not settle.

## Build and run

```bash
mvn -B clean verify                          # build + tests
NVD_API_KEY=... mvn -B -Powasp verify   # OWASP Dependency-Check scan
mvn spring-boot:run -Dspring-boot.run.profiles=dev   # local run without TLS, port 8082
java -jar target/railgate-1.8.0.jar          # deployed: needs server.ssl (see below)
```

railgate does not start without TLS on its own listener
(`ListenerTlsGuard`): configure `server.ssl.bundle` (or
`server.ssl.key-store` / `server.ssl.certificate`). The `/api/v1/**`
credentials and the settlement verdicts would otherwise travel in clear.
The `dev` profile sets `railgate.server.allow-insecure-http=true` for a
local run; never set it in a deployed configuration. Request bodies are
capped at `railgate.limits.max-http-request-size` (default 16 KB,
`RequestSizeLimitFilter`); a settlement request is well under 1 KB.

Configuration via `application.yml`:

| Property                                    | Default                  | Purpose                                                                 |
|---------------------------------------------|--------------------------|-------------------------------------------------------------------------|
| `railgate.payment-network.mode`             | `in-memory`              | Payment-network operator client implementation: `in-memory`; `file` for local end-to-end runs only; or *(1.7.0)* `http`, the client for the operator interface in `api/payment-network-operator.openapi.yaml` |
| `railgate.payment-network.file`             | *(empty)*                | Required when the mode is `file`: tab-separated artefacts (reference, certificate serial, issuer DN, digest, signature), re-read on every lookup. Not for production. |
| `railgate.payment-network.base-url`         | *(empty)*                | `http` mode, required: the operator's base URL; railgate calls `GET {base-url}/v1/payout-artefacts/{ref}`. Must be `https://` unless the flag below is set. |
| `railgate.payment-network.allow-insecure-http` | `false`               | Permit an `http://` operator base URL; logs a WARN. Local development only. |
| `railgate.payment-network.ssl-bundle`       | *(empty)*                | Spring Boot SSL bundle with the mTLS client certificate and the truststore for the operator. Empty means JVM defaults; a bundle with ciphers or protocols set is refused at start-up. |
| `railgate.payment-network.connect-timeout`  | `PT2S`                   | Connect timeout for the operator; must be positive. |
| `railgate.payment-network.read-timeout`     | `PT5S`                   | Time allowed for the operator's whole answer, from the request to its last byte; must be positive. Until 1.7.0 it bounded each read, not the answer. |
| `railgate.payment-network.trusted-keys`     | *(empty)*                | `http` mode, required: PEM file (`classpath:`, `file:` or a path) with the operator's signing certificate(s). Missing, unreadable or empty stops start-up. |
| `railgate.gatekeeper.base-url`              | `https://localhost:8443` | Supervisor's gatekeeper instance URL. Must be `https://` unless the flag below is set. |
| `railgate.gatekeeper.allow-insecure-http`   | `false`                  | Permit a non-`https` base URL. Local development only — start-up fails without it, and logs a WARN with it. |
| `railgate.gatekeeper.connect-timeout`       | `PT2S`                   | TCP connect timeout for gatekeeper calls (ISO-8601 duration); must be positive. |
| `railgate.gatekeeper.read-timeout`          | `PT5S`                   | Time allowed for the gatekeeper's whole answer, from the request to its last byte (ISO-8601 duration); must be positive. Exceeding either yields `NETWORK_ERROR` and a deny, as do an answer over 65 536 bytes and any status other than 2xx. Until 1.7.0 this timeout bounded each read, not the answer, and zero meant no timeout. |
| `railgate.gatekeeper.ssl-bundle`            | *(empty)*                | Name of a Spring Boot SSL bundle (`spring.ssl.bundle.*`) whose trust and key material is used for the gatekeeper connection. Empty means the JVM default SSL context. An unknown name fails start-up. |
| `railgate.gatekeeper.trusted-keys`          | *(empty)*                | *(1.7.0)* PEM file with the gatekeeper's verdict-signing certificate(s) — the certificate `GET /v1/gatekeeper/keys` publishes. Set but unreadable or without a certificate stops start-up; empty with a signature required starts with a WARN and denies every settlement that reaches the gatekeeper. |
| `railgate.gatekeeper.require-signed-verdict` | `true` (`false` in `dev`) | *(1.7.0)* Require a signed gatekeeper verdict. `false` logs a WARN ("MUST NOT be deployed"). |
| `railgate.gatekeeper.verdict-max-skew`      | `PT60S`                  | *(1.7.0)* Largest accepted distance between the verdict's `verifiedAt` and railgate's clock, either direction; zero allowed, negative stops start-up. |
| `railgate.replay.path`                      | *(empty)*                | *(1.7.0)* Journal of allowed references and payout instruction ids. Empty: in memory only, lost on restart, with a WARN at start-up. The parent directory must exist. |
| `railgate.regulated.local-instrument-codes` | `SWISH`                  | LclInstrm/Cd values that identify regulated payments. Matched case-insensitively, whitespace-trimmed. |

## Transport and authentication

**Outbound, railgate → gatekeeper.** The base URL must be `https://`;
`GatekeeperClient` throws `IllegalStateException` at start-up otherwise, so
a plain-HTTP supervisor link is a boot failure rather than a silent
downgrade. Trust and key material come from one of two places:

- **An SSL bundle.** Define it with Spring Boot's standard properties —
  `spring.ssl.bundle.jks.<name>.truststore.*` for the gatekeeper's CA and
  `spring.ssl.bundle.jks.<name>.keystore.*` for the client certificate
  where the gatekeeper requires mTLS (or the `pem` equivalents) — and set
  `railgate.gatekeeper.ssl-bundle=<name>`. `GatekeeperClient` resolves the
  bundle at start-up and uses its `SSLContext` for every gatekeeper
  connection. gatekeeper's `SETTLEMENT_RAIL` role is bound to the client
  certificate's CN. Two limits: railgate applies the bundle's key and
  trust material only, so a bundle that sets `options.ciphers` or
  `options.enabled-protocols` is refused at start-up rather than silently
  ignored; and the context is built once, so a bundle with
  `reload-on-update: true` takes effect for railgate only at the next
  restart.
- **The JVM defaults** (`javax.net.ssl.trustStore`, `javax.net.ssl.keyStore`
  and their passwords), when `railgate.gatekeeper.ssl-bundle` is empty.

A reverse proxy or service mesh that terminates the mTLS to the gatekeeper
on railgate's behalf (an egress proxy) is an equally valid arrangement; in
that case point `base-url` at the proxy. This concerns the outbound link
only: railgate's own listener must still have TLS (`ListenerTlsGuard`).

**railgate verifies the gatekeeper's signed verdict** *(since 1.7.0)*.
Up to 1.6.0 the verdict was plain JSON and its integrity rested entirely on
the transport: an attacker who could terminate or rewrite the TLS session
could return `allow`. gatekeeper 1.7.0 signs every `POST /api/v1/verify`
response, denials included, with its receipt key over the canonical form

```
sv1|verifiedAt|certSerialHex|issuerDn|digestHex|signatureValid|compliant|reason|auditEntryId|auditEntryHashHex
```

and returns `verifiedAt`, `verdictSignatureBase64`,
`verdictSignatureAlgorithm` and `signingKeyFingerprintHex` beside the
verdict. `GatekeeperClient` (`VerdictVerifier`) checks, in this order:

1. all four fields are present and non-blank;
2. `signingKeyFingerprintHex` selects a certificate in
   `railgate.gatekeeper.trusted-keys`;
3. `verdictSignatureAlgorithm` is on the allow-list (`SHA256withRSA`,
   `SHA384withRSA`, `SHA512withRSA`, `SHA256withECDSA`, `SHA384withECDSA`,
   `SHA512withECDSA`, `Ed25519`; exact spelling);
4. the signature verifies under that certificate over `sv1` built from the
   `certSerial`, `issuerDn` and `digestHex` railgate **sent** (normalised:
   serial without `0x`/`0X` as lower-case hex without leading zeros, issuer
   in RFC 2253 form, digest lower-cased) and the other fields of the
   verdict, so a verdict signed for other identifiers or another digest
   does not verify (the form does not cover the signature bytes or a
   certificate added to the request; gatekeeper 1.8.0 or later looks
   the certificate up under `certSerial` and `issuerDn` in every case, see
   `THREAT_MODEL.md`);
5. any echoed `certSerial`, `issuerDn` or `digestHex` equals what was sent;
6. `verifiedAt` parses as an instant;
7. `|now − verifiedAt|` is at most `railgate.gatekeeper.verdict-max-skew`.

Steps 1–6 failing is `VERDICT_SIGNATURE_INVALID`, step 7 `VERDICT_STALE`
(reported only for an authentic verdict). The fingerprint is the lowercase
hex SHA-256 of the signing certificate's DER SubjectPublicKeyInfo, 64
characters without separators — the `publicKeyFingerprintHex` that
gatekeeper publishes on `GET /v1/gatekeeper/keys`, not the SHA-256 of the
certificate — so a certificate reissued for the same key keeps its
fingerprint. At start-up railgate logs the fingerprints it computed for
`trusted-keys`. Only the certificates in that file are trusted: their
validity and revocation are not checked, and withdrawing one means
removing it and restarting.

A signed verdict is required by default. With
`railgate.gatekeeper.require-signed-verdict=false` (the `dev` profile; logged
at WARN) an unsigned verdict is used as before and recorded as `UNSIGNED`,
and a signed one is still verified when `trusted-keys` is set, otherwise
used unchecked and recorded as `UNVERIFIED`. With the requirement on but no
`trusted-keys`, railgate starts with a WARN and denies every settlement
that reaches the gatekeeper. `sv1` carries no per-call nonce: a genuine
verdict for an identical `(certSerial, issuerDn, digestHex)` can be
presented again within the skew window. The transport requirements above
still apply. See `THREAT_MODEL.md`.

**railgate → payment-network operator** *(since 1.7.0, `http` mode)*. See
"Payment-network operator interface" below: `https://` required (unless
`railgate.payment-network.allow-insecure-http=true`), mTLS through
`railgate.payment-network.ssl-bundle`, and every answer signed by the
operator.

**Inbound, settlement rail → railgate.** `SecurityConfig` requires
authentication on every path, with CSRF disabled and sessions stateless:
one filter chain for `/api/v1/**` and everything else alike (no form login,
no logout endpoint). A request without credentials is answered `401` and
leaves no session behind. *(Changed 1.8.0: until then everything outside
`/api/v1/**` was behind a second chain that kept Spring Boot's default
posture — form login and sessions — and each unauthenticated request to
such a path created a server session that lived for 30 minutes.)* The
mechanism is the deployer's choice and is not fixed by this repo:

- **mTLS** (what a central-bank deployment should use). Configure
  `server.ssl.client-auth=need` with a truststore holding the settlement
  system's CA, then replace `.httpBasic(...)` on the chain with
  `.x509(x509 -> x509.x509PrincipalExtractor(...))`. gatekeeper's
  `SecurityConfig` shows the full arrangement including principal
  extraction and role mapping.
- **HTTP Basic** (what ships). Usable immediately; Spring Boot generates a
  password at start-up unless `spring.security.user.*` is set.

railgate has no role model of its own — every caller of `/api/v1/**` is the
settlement rail — so the chain authenticates without authorising further.

## Payment-network operator interface

railgate needs, for each regulated settlement, the digest, signature and
certificate identifiers the originating bank submitted with the payout
instruction. No operator offers an interface for that today. Since 1.7.0
`api/payment-network-operator.openapi.yaml` (OpenAPI 3.0.3) specifies one,
so that it can be required of an operator, for example through
participation conditions, and `HttpPaymentNetworkClient`
(`railgate.payment-network.mode=http`) implements the client side.

- `GET {base-url}/v1/payout-artefacts/{transactionReference}` over mutual
  TLS (stated in the description and marked `x-mutual-tls-required`;
  OpenAPI 3.0 has no mTLS security scheme). railgate percent-encodes every
  octet of the reference except `A-Z a-z 0-9 - . _ ~`, follows no
  redirects and applies the configured timeouts. It does not request the
  references `.` and `..` *(1.8.0)*: as a path segment each names a
  directory, which a server or proxy resolves away, so the request would
  reach another path. They are answered `DORA_32_AUDIT_MISSING` without a
  call.
- 200 answers `PayoutArtefacts`: `transactionReference`,
  `payoutInstructionId` (the operator's own identifier, 1–64 printable
  ASCII characters), `certSerial`, `issuerDn`, `digestHex`,
  `signatureBase64`, `issuedAt`, and the operator's
  `operatorSignatureBase64`, `operatorSignatureAlgorithm` and
  `operatorKeyFingerprintHex`. The operator signs the first seven over
  `op1|transactionReference|payoutInstructionId|certSerialHex|issuerDn|digestHex|signatureBase64|issuedAt`
  (normalisation and escaping as in the specification, which also gives a
  worked example and its SHA-256). The fingerprint follows the gatekeeper's
  `/keys` convention (SHA-256 of the DER SubjectPublicKeyInfo).
- railgate accepts a 200 only if the body is at most 65 536 bytes of JSON
  without duplicate keys, all ten properties are strings,
  `transactionReference` is exactly the one requested, `payoutInstructionId`
  matches its pattern, the `op1` bytes can be built, the fingerprint selects
  a certificate in `railgate.payment-network.trusted-keys`, the algorithm is
  on the allow-list and the signature verifies. Anything else is
  `OPERATOR_SIGNATURE_INVALID`, and the gatekeeper is not called. 404 is
  `DORA_32_AUDIT_MISSING`; any other status, a redirect, a timeout or a
  transport failure is `NETWORK_ERROR`.
- Not checked: the response `Content-Type`, the format and age of
  `issuedAt`, and the validity and revocation of the pinned operator
  certificates. Unknown properties are ignored and are not covered by the
  signature.

The operator's signature makes it accountable for the answer it gave; it
does not show that the artefacts are those the bank submitted, nor that the
operator holds no others for the reference. The client is tested against a
reference operator built on `com.sun.net.httpserver` (with and without
mTLS), not against Getswish AB or any real operator, and which field of
Swish's payout API corresponds to `payoutInstructionId` is not established.
The `in-memory` and `file` modes behave as before and carry no
`payoutInstructionId`.

## Replay protection

*(Since 1.7.0.)* `ReplayGuard` allows each transaction reference, and each
operator `payoutInstructionId`, at most once:

- After the artefacts are found and the declared serial is checked, both
  keys are reserved atomically. A key already allowed, or held by another
  evaluation in flight, is refused at once with `REFERENCE_ALREADY_SETTLED`
  (the second evaluation does not wait), and the gatekeeper is not called.
- An allow commits both keys; a deny, or an exception before the commit,
  releases them, so a denied settlement can be resubmitted.
- With `railgate.replay.path` set, the commit appends one line
  (`v1`, the URL-encoded reference, the URL-encoded payout id, the instant)
  and forces it to disk before the allow is returned. The journal is held
  under an exclusive file lock (a second process or guard fails start-up),
  a torn last record is truncated at start-up with a WARN, any other
  unreadable line stops start-up, and after a failed write every later
  allow is `INTERNAL_ERROR` until restart. Without the path the record is
  in memory and lost on restart, with a WARN at start-up.
- `NOT_REGULATED` pass-throughs are neither checked nor recorded.

Limits: the record is local to one instance; it is never pruned; it is not
tamper-evident (no hash chain or signature, no file permissions set); and a
reference that railgate allowed but whose settlement failed downstream
cannot be allowed again.

## Endpoints

| Method | Path                          | Purpose                                          |
|--------|-------------------------------|--------------------------------------------------|
| POST   | `/api/v1/settle/precheck`     | Pre-settlement verification (returns allow/deny) |
| GET    | `/api/v1/audit`               | Audit trail of railgate decisions                |
| GET    | `/api/v1/audit/health`        | Retained, capped and discarded audit-entry counts |
| GET    | `/swagger-ui.html`            | OpenAPI documentation — `dev` profile only       |

`/swagger-ui.html` and `/v3/api-docs` are served only with
`--spring.profiles.active=dev` (`application-dev.yml`); every other profile
has `springdoc.api-docs.enabled=false` and `springdoc.swagger-ui.enabled=false`.
The Swagger UI package itself is not served under `/webjars/**` in any
profile (`spring.web.resources.add-mappings=false`). *(1.8.0: until then
Spring Boot's default mapping served it there in every profile, to any
authenticated caller, and in the `dev` profile `/swagger-ui.html` redirected
to a page that was not found, because springdoc looked for another version
of the package than the one `pom.xml` pins.)*

Sample precheck request. `transactionReference`, `debtorIsOrganization`
and `creditorIsPrivatePerson` are required; omitting either flag is a 400,
not a pass-through. The response is the `SettlementDecision` (`allow`,
`reasonCode`, `message`, the transaction reference and the gatekeeper
references) and, since 1.7.0, `verdictSignature`, which is `null` on a
decision taken without a gatekeeper verdict.

```json
{
  "transactionReference": "UETR-12345",
  "localInstrumentCode": "SWISH",
  "debtorIsOrganization": true,
  "creditorIsPrivatePerson": true,
  "debtorBic": "ESSESESS",
  "creditorBic": "HANDSESS"
}
```

## Legal basis

See `pom.xml` `<description>` for the full list of Union and Swedish
national-law provisions on which this implementation is based.

## License

MIT — see [`LICENSE`](LICENSE).

## Citation

See [`CITATION.cff`](CITATION.cff). When citing, please cite all three
companion artefacts together where appropriate.
