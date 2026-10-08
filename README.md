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
quadruple-triangulation model. Each component answers one specific
question:

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
   railgate → Getswish.getSignature(transactionReference)
       ↓
   railgate → gatekeeper.verify(certSerial, issuerDn, digest, signature)
       ↓
   gatekeeper (1.5.0 or later):
     1. Look up cert stored at Step 7 via (certSerial, issuerDn)
     2. Signature.getInstance("SHA512withRSA")
          .initVerify(publicKey); update(digest); verify(signature)
     3. Check compliance status of audit entry
     4. Return {signatureValid, compliant, reason}
       ↓
   railgate decides: allow ↔ default-deny (block settlement)
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
denied. railgate 1.5.0 requires gatekeeper 1.5.0 or later.

**Wire contract.** railgate sends exactly four JSON properties, which are
the required fields of gatekeeper's `SignatureVerificationRequest`:

| Property          | Format                                                                 | Gatekeeper limit        |
|-------------------|------------------------------------------------------------------------|-------------------------|
| `certSerial`      | Hexadecimal, case-insensitive, optional `0x` prefix. Compared numerically (`BigInteger`), so `0x00C0FFEE` and `c0ffee` are the same serial. Not decimal. | `@NotBlank`, `@Size(max = 128)` |
| `issuerDn`        | RFC 4514 string, e.g. `CN=Example CA,O=Example Bank,C=SE`. Compared by `X500Principal` equality. | `@NotBlank`, `@Size(max = 512)` |
| `digestHex`       | SHA-512, exactly 128 hexadecimal characters.                           | `@NotBlank`, `@Size(max = 256)` |
| `signatureBase64` | Standard base64.                                                       | `@NotBlank`, `@Size(max = 4096)` |

`signingCertificatePem` and `algorithm` are never sent. `GatekeeperClient`
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
the reason code and two gatekeeper references — not the BICs and not the
flags. `gatekeeperAuditEntryId` is the gatekeeper's approval-registry
`verificationId`, shared by every settlement against the same certificate
and `null` on `CERT_NOT_FOUND`; `gatekeeperAuditEntryHashHex` (gatekeeper
1.5.0 and later) is the hash of the gatekeeper's own `SETTLEMENT_VERIFY`
audit entry for the call, which identifies that one decision in the
gatekeeper's hash-chained log.

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
artefacts up by transaction reference and never records a reference as
consumed. A settlement that carries the reference of an earlier, genuinely
signed payout therefore receives that payout's artefacts, verifies, and is
allowed — whoever submits it, including the originating bank itself.
Whether a reference can settle twice depends on the settlement rail's own
duplicate detection, not on railgate. A replay store is not added in this
release: it would have to survive restarts, be shared across instances,
and distinguish a replay from a legitimate resubmission after a deny or a
downstream settlement failure, and an in-memory set does none of that.

Closing the first requires the settlement message to carry the signed
fields; closing the second requires the payment-network operator or the
rail to bind each set of artefacts to a single settlement. Both are
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
and 413 (`{"error":"request_too_large"}`) from `RequestSizeLimitFilter` for
an oversized body. A pipeline must treat both as a deny.

| Reason code                | HTTP | allow | Meaning                                                            |
|----------------------------|------|-------|--------------------------------------------------------------------|
| ALLOWED                    | 200  | true  | Signature verified and certificate compliant; settlement proceeds.  |
| NOT_REGULATED              | 200  | true  | Explicitly classified, and not organisation-to-private. Passed through without verification. |
| DORA_32_AUDIT_MISSING      | 403  | false | No signature artefacts found at the payment-network operator.       |
| DECLARED_CERT_MISMATCH     | 403  | false | The settlement request declares a certificate serial (`declaredCertSerial`, from pacs.008 `RgltryRptg`) that differs numerically from the payment-network operator's, or is not hexadecimal. The gatekeeper was not called. |
| CERT_NOT_FOUND             | 403  | false | Certificate matches no gatekeeper audit entry — issuance was circumvented, or the wrong certificate was used. |
| SIGNATURE_INVALID          | 403  | false | Cryptographic verification failed at the gatekeeper.                |
| CERT_NON_COMPLIANT         | 403  | false | Certificate exists but was not issued through a compliant flow.     |
| CERT_EXPIRED               | 403  | false | The signature verifies, but the certificate is outside its validity period (gatekeeper 1.6.0). |
| MALFORMED_INPUT            | 403  | false | The gatekeeper could not parse the request. Not a signature failure. |
| ALGORITHM_NOT_SUPPORTED    | 403  | false | The gatekeeper would not run the signature algorithm. Not a signature failure. |
| NETWORK_ERROR              | 403  | false | gatekeeper unreachable, timed out, or returned an unusable body.    |
| INVALID_SIGNATURE_MATERIAL | 403  | false | The artefacts from the payment-network operator are malformed or outside the wire contract above (digest not 128 hex characters, signature not base64 or over 4096 characters, certificate serial not hexadecimal or over 128 characters, issuer DN not an RFC 4514 name or over 512 characters, any of them blank). The gatekeeper was not called. |
| INVALID_REQUEST            | 400  | false | The settlement request failed Bean Validation — a missing party-type flag, a blank or over-36-character transaction reference, an over-long instrument code, declared certificate serial (128) or BIC (11). No verification was attempted. |
| INTERNAL_ERROR             | 403  | false | Any unhandled failure inside railgate. Default-deny; no detail about the failure is returned to the caller. |

`CERT_NOT_FOUND`, `CERT_NON_COMPLIANT`, `CERT_EXPIRED`, `SIGNATURE_INVALID`,
`MALFORMED_INPUT` and `ALGORITHM_NOT_SUPPORTED` are read from the
gatekeeper's own `reason` field and passed through unchanged, as are
`NETWORK_ERROR` and `INVALID_SIGNATURE_MATERIAL`, which railgate's client
produces itself. That is every non-positive reason the gatekeeper
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
NVD_API_KEY=... mvn -B -Powasp verify -DnvdApiKeyEnvironmentVariable=NVD_API_KEY   # OWASP Dependency-Check scan
mvn spring-boot:run -Dspring-boot.run.profiles=dev   # local run without TLS, port 8082
java -jar target/railgate-1.6.0.jar          # deployed: needs server.ssl (see below)
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
| `railgate.payment-network.mode`             | `in-memory`              | Payment-network operator client implementation: `in-memory`, or `file` for local end-to-end runs only |
| `railgate.payment-network.file`             | *(empty)*                | Required when the mode is `file`: tab-separated artefacts (reference, certificate serial, issuer DN, digest, signature), re-read on every lookup. Not for production. |
| `railgate.gatekeeper.base-url`              | `https://localhost:8443` | Supervisor's gatekeeper instance URL. Must be `https://` unless the flag below is set. |
| `railgate.gatekeeper.allow-insecure-http`   | `false`                  | Permit a non-`https` base URL. Local development only — start-up fails without it, and logs a WARN with it. |
| `railgate.gatekeeper.connect-timeout`       | `PT2S`                   | TCP connect timeout for gatekeeper calls (ISO-8601 duration)            |
| `railgate.gatekeeper.read-timeout`          | `PT5S`                   | Response read timeout for gatekeeper calls (ISO-8601 duration). Exceeding either yields `NETWORK_ERROR` and a deny. |
| `railgate.gatekeeper.ssl-bundle`            | *(empty)*                | Name of a Spring Boot SSL bundle (`spring.ssl.bundle.*`) whose trust and key material is used for the gatekeeper connection. Empty means the JVM default SSL context. An unknown name fails start-up. |
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
  certificate's CN. Two limits: the connection is made with the JDK
  `HttpURLConnection`, so a bundle that sets `options.ciphers` or
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

**railgate does not verify signed gatekeeper responses.** The gatekeeper
signs its receipts, and the verdict railgate consumes is not one of them:
`POST /api/v1/verify` returns plain JSON, and `GatekeeperClient`
deserialises `signatureValid` and `compliant` without checking any
signature over them. The integrity of the verdict therefore rests entirely
on the transport and on the gatekeeper's own controls. An attacker who can
terminate or rewrite the TLS session can return `allow`. This is why the
`https://` requirement is enforced rather than recommended, and it is the
reason mTLS matters here beyond authentication. See `THREAT_MODEL.md`.

**Inbound, settlement rail → railgate.** `SecurityConfig` requires
authentication on `/api/v1/**` with CSRF disabled and sessions stateless;
everything else keeps Spring Boot's default posture. The mechanism is the
deployer's choice and is not fixed by this repo:

- **mTLS** (what a central-bank deployment should use). Configure
  `server.ssl.client-auth=need` with a truststore holding the settlement
  system's CA, then replace `.httpBasic(...)` on the `/api/v1/**` chain
  with `.x509(x509 -> x509.x509PrincipalExtractor(...))`. gatekeeper's
  `SecurityConfig` shows the full arrangement including principal
  extraction and role mapping.
- **HTTP Basic** (what ships). Usable immediately; Spring Boot generates a
  password at start-up unless `spring.security.user.*` is set.

railgate has no role model of its own — every caller of `/api/v1/**` is the
settlement rail — so the chain authenticates without authorising further.

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

Sample precheck request. `transactionReference`, `debtorIsOrganization`
and `creditorIsPrivatePerson` are required; omitting either flag is a 400,
not a pass-through.

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
