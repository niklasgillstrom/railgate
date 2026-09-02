# Changelog — railgate

This file starts at 1.4.0. Earlier releases are documented in the git history, in `PEER_REVIEW_GUIDE.md` and in `CROSS_REFERENCE.md`.

## 1.4.0

Every item below is a defect that was present in 1.3.0. Where a defect had a reason for surviving review, that reason is stated rather than left out.

### Start-up blocker

- **1.3.0 could not start.** `GatekeeperClient` was given a package-private `GatekeeperClient(RestTemplate)` constructor as a test seam, alongside the public `@Value` constructor. Neither carried `@Autowired` and the class has no no-arg constructor, so Spring had two candidates and no way to choose: context refresh failed and the service did not boot.

  The seam and the defect arrived in the same commit. 1.3.0's headline fix was the connect and read timeout on the outbound gatekeeper call — an unresponsive gatekeeper had been blocking the calling thread instead of producing a deny — and `GatekeeperClientTest` was written at the same time to cover it. Adding the seam is what made the constructor ambiguous. **The timeout fix has therefore never executed in a deployed instance.** It was correct, it was tested, and it was unreachable, because the bean it lives on could not be created.

  Nothing caught this, because no test in the repository loaded the Spring context. `SettlementOrchestratorTest` constructs its collaborators with `new` and injects the detector's configuration by reflection; `GatekeeperClientTest` uses the seam and sets the base URL with `ReflectionTestUtils`. Neither reads `application.yml` and neither builds the bean graph, so a green suite said nothing about whether the application starts. `@Autowired` is now on the public constructor, the seam is retained, and `ApplicationContextLoadsTest` boots the real context from the real configuration so that this class of failure surfaces in CI rather than on a host.

### Security

- **A settlement with no party-type classification was passed through with `allow=true`.** `debtorIsOrganization` and `creditorIsPrivatePerson` were `boolean` primitives. A JSON payload that omitted them deserialised to `false, false`, which `RegulatedPaymentDetector` read as a private-to-private transfer — the one shape railgate does not verify. The minimal payload `{"transactionReference": "..."}` therefore produced `NOT_REGULATED`, `allow=true`, without any call to the gatekeeper. Both fields are now `Boolean` with `@NotNull`, so an omission fails validation; a request that reaches the detector without them is treated as regulated; and `SettlementOrchestrator` requires the classification to be present before it will take the pass-through path at all, so the invariant does not depend on the detector alone. `localInstrumentCode` is bounded at `@Size(max = 35)`, the ISO 20022 `Max35Text` length.

- **Local-instrument-code matching was exact and case-sensitive.** `"swish"` and `" SWISH"` did not match the configured `SWISH`. Matching is now case-insensitive and trimmed on both sides.

- **The documented claim that structural derivation "cannot be circumvented by the originating bank" was not true of the code,** and is corrected in `README.md`, `PEER_REVIEW_GUIDE.md`, `CROSS_REFERENCE.md` and the class javadoc. Both party-type flags are metadata: the settlement system derives them from `Dbtr/Id/OrgId` and `Cdtr/Id/PrvtId` and hands them to railgate in `SettlementRequest`. railgate does not receive the pacs.008, does not parse it, and cannot recompute the derivation. What is now true, and is what the documents say, is that the structural path is harder to suppress than the instrument code and that a missing classification is treated as regulated.

- **The gatekeeper base URL must be `https://`.** The default was `http://localhost:8080` and nothing checked the scheme, so a deployment that left the default in place sent the digest, signature and certificate identifiers in clear text and accepted the verdict back the same way. New key `railgate.gatekeeper.allow-insecure-http` (default `false`); a non-`https` URL without it is an `IllegalStateException` at start-up, and with it a WARN at every start-up. The default is now `https://localhost:8443`.

- **`THREAT_MODEL.md` claimed a protection the code does not implement.** It stated that "the gatekeeper's signed response is what the orchestrator allows on" and that "a fraudulent unsigned response cannot mimic it". `POST /api/v1/verify` returns plain JSON; `GatekeeperClient` deserialises `signatureValid` and `compliant` and verifies no signature over them. The gatekeeper signs its receipts, and the settlement-time verdict is not one of them. The Spoofing, Tampering, Denial-of-service and Elevation-of-privilege sections now describe what the code does — including that there is no role model at the railgate side, no certificate pinning and no rate limiting — and the unsigned verdict is written up as a residual with what closing it would require.

- **Cryptographic material is checked before it is forwarded.** `digestHex` must be exactly 128 hexadecimal characters, `signatureBase64` must decode with `Base64.getDecoder()`, and `certSerial` and `issuerDn` must be non-blank. Otherwise the gatekeeper is not called and the result is `signatureValid=false, compliant=false, reason=INVALID_SIGNATURE_MATERIAL`. Malformed artefacts from the payment-network operator previously consumed a supervisory call and came back as `SIGNATURE_INVALID`, which is an accusation against the originating bank for a defect that is not theirs.

- **An unhandled exception no longer produces an HTTP 500 with a body that is not a `SettlementDecision`.** New `SettlementExceptionHandler` (`@RestControllerAdvice`, scoped to `SettlementController`) returns 403 with `allow=false, reasonCode=INTERNAL_ERROR` for anything unhandled and 400 with `allow=false, reasonCode=INVALID_REQUEST` for a validation failure. Neither response carries the exception message, class name or field-level validation detail; the operator's log gets the stack trace. Both outcomes are written to the audit log, because a denied settlement that left no record is indistinguishable afterwards from one that was never submitted.

- **`/api/v1/**` has a security configuration.** `spring-boot-starter-security` was on the classpath with no `SecurityFilterChain` bean, so Boot's default applied to a stateless machine-to-machine JSON API: session-based, CSRF-protected, form login. New `SecurityConfig` gives `/api/v1/**` a stateless, CSRF-exempt, authenticated chain and reproduces the Boot default for everything else. The authentication mechanism is the deployer's choice — HTTP Basic ships, mTLS with `.x509(...)` is what a central-bank deployment should use — and `README.md` documents how to wire it. railgate has no role model: every authenticated caller of `/api/v1/**` can both submit prechecks and read the audit trail. `THREAT_MODEL.md` previously claimed a `SETTLEMENT_RAIL` role at the railgate side that the reference configuration never contained; `SETTLEMENT_RAIL` exists at the gatekeeper.

- **Log injection via `transactionReference` and `message`.** Both come from upstream and both are written to a line-oriented log, so an embedded CR or LF let the writer forge additional log lines in the supervisory record. They are flattened to spaces before the entry is stored or logged, and `message` is capped at 512 characters.

### Correctness

- **`CERT_NOT_FOUND` is reported as `CERT_NOT_FOUND`.** `reasonCodeFor` derived the code from `signatureValid` and `compliant`, testing only for `NETWORK_ERROR` before that. A gatekeeper answer of `CERT_NOT_FOUND` — the certificate matches no audit entry, i.e. issuance was circumvented, which is the case the whole triad exists to detect — arrived at the originating bank as `SIGNATURE_INVALID`. The gatekeeper's `reason` is now read first and passed through when it is one of `CERT_NOT_FOUND`, `CERT_NON_COMPLIANT`, `SIGNATURE_INVALID`, `NETWORK_ERROR` or railgate's own `INVALID_SIGNATURE_MATERIAL`; anything else falls back to the boolean derivation.

  `INVALID_SIGNATURE_MATERIAL` is in that set although it is not a gatekeeper value: it is produced by `GatekeeperClient` before any call, and mapping it to `SIGNATURE_INVALID` would reintroduce exactly the conflation the 1.3.0 `NETWORK_ERROR` fix removed.

- **The unreachable `VERIFICATION_FAILED` branch is removed.** `reasonCodeFor` is called only when `!isAllowed()`, so either the signature did not verify or it did and the certificate was not compliant. There is no third case and the branch could not be reached. `VERIFICATION_FAILED` no longer appears in `README.md`'s reason-code table either.

### Observability

- **Audit-log eviction is counted and reported.** The 10 000-entry ring buffer introduced in 1.3.0 discarded its oldest records silently, so a gap in the supervisory record was invisible from the snapshot. Discards are counted, a WARN is emitted once per thousand, and `GET /api/v1/audit/health` returns `{entryCount, maxEntries, evictedCount}`.

### Configuration

- **OpenAPI document and Swagger UI are off unless the `dev` profile is active.** `springdoc.api-docs.enabled` and `springdoc.swagger-ui.enabled` are `false` in every shipped configuration file; the new `application-dev.yml` turns them on for local use. Neither endpoint has a run-time function in this service, and swagger-ui is a third-party JavaScript application whose vulnerabilities (see Dependencies) would otherwise be part of the deployed surface.

- New key `railgate.gatekeeper.allow-insecure-http` (default `false`), set in `application.yml`.
- `railgate.gatekeeper.base-url` default changed from `http://localhost:8080` to `https://localhost:8443`.
- `railgate.gatekeeper.connect-timeout` and `railgate.gatekeeper.read-timeout` existed in 1.3.0 but were undocumented; both are now in the configuration tables in `README.md` and `PEER_REVIEW_GUIDE.md`.

### API changes

- `SettlementRequest.debtorIsOrganization` and `creditorIsPrivatePerson` change from `boolean` to `Boolean` and become `@NotNull`. The JSON property names are unchanged, but a payload that omitted them and previously succeeded now receives 400. Callers must supply both.
- `SettlementRequest.localInstrumentCode` gains `@Size(max = 35)`.
- `GatekeeperClient`'s public constructor takes the base URL and the insecure-HTTP flag in addition to the two timeouts. The base URL moved from an injected field to a constructor argument because the scheme check has to run at start-up rather than on the first settlement.
- New reason codes `INVALID_SIGNATURE_MATERIAL`, `INVALID_REQUEST`, `INTERNAL_ERROR`. `VERIFICATION_FAILED` removed.
- New endpoint `GET /api/v1/audit/health`.
- New `RailgateAuditLog.AuditLogHealth` record, `RailgateAuditLog.health()` and `RailgateAuditLog.getEvictedCount()`.

### Tests

`mvn -B test` runs 39 tests, up from 11. New: `ApplicationContextLoadsTest` (2), `OpenApiExposureDefaultProfileTest` (2), `OpenApiExposureDevProfileTest` (2), `SettlementRequestValidationTest` (4), `SettlementExceptionHandlerTest` (4), seven cases added to `SettlementOrchestratorTest` and seven to `GatekeeperClientTest`. `GatekeeperClientTest.forwardsExactlyTheFourDataMinimisedFields` now uses a 128-character digest, since a short one is rejected before the call.

### Dependencies

- Spring Boot parent 4.1.1 (Spring Framework 7, Spring Security 7), Lombok 1.18.48, springdoc-openapi 3.1.0.
- `org.webjars:swagger-ui` is pinned to 5.32.14. springdoc 3.1.0 ships 5.32.11, which bundles DOMPurify 3.4.12 (CVE-2026-75838). The earlier suppression for DOMPurify 3.3.2 (CVE-2026-41238/41239/41240) no longer matches anything and has been removed from `.owasp-suppressions.xml`; the file is now empty.
- `tomcat.version` is overridden to 11.0.25. Boot 4.1.1 manages 11.0.24, for which OWASP Dependency-Check reports eleven CVEs (CVE-2026-65182, -65183, -65637, -65905, -65927, -66299, -66422, -68525, -68569, -68763, -73180); all are listed as fixed in Tomcat 11.0.25 (2026-08-18). The override is to be removed once the parent manages 11.0.25 or later.
- `dependency-check-maven` stays at 12.2.2. 13.0.0 rejects an absent NVD API key as an invalid key of length 0 (jeremylong/DependencyCheck#8715), and this project is scanned without a key. The `<nvdApiKey>` configuration has been removed for the same reason.

### Documentation

- `README.md`: the architecture diagram's verification step was written in Node.js (`createVerify('sha512WithRSAEncryption')`) for a Java implementation that calls `Signature.getInstance("SHA512withRSA")`. The data-minimisation section listed four fields as everything railgate handles, omitting the debtor and creditor BICs and the two party-type flags that `SettlementRequest` also carries; the section now separates what railgate receives from what it forwards to the supervisor, which is the boundary the claim is actually about. The reason-code table is replaced with the complete reachable set and its HTTP statuses, new sections cover transport and authentication, the configuration table carries the timeouts and the new flag, and the run instructions name `railgate-1.4.0.jar`.
- `PEER_REVIEW_GUIDE.md`: expected test count, the seven-field `SettlementRequest` (documented as four), the extension-point list, the configuration knobs, the reason-code enumeration and the corrected non-circumventability claim.
- `CROSS_REFERENCE.md`: the two `[RG]` rows — corrected non-circumventability claim, updated test counts, and the unsigned gatekeeper verdict noted where the quadruple-triangulation claim is made.
- `THREAT_MODEL.md`: see under Security above.
