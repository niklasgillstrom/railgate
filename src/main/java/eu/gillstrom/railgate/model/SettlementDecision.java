package eu.gillstrom.railgate.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Final outcome returned by railgate for a settlement request.
 *
 * <p>{@code allow} = true indicates the settlement may proceed.
 * {@code allow} = false indicates default-deny: the originating bank
 * receives a structured error and must resubmit with valid data, or the
 * transaction does not settle at all.
 *
 * <p>{@code reasonCode} is one of:
 * <ul>
 *   <li>{@code ALLOWED} — verification passed, settle.</li>
 *   <li>{@code NOT_REGULATED} — not subject to railgate enforcement;
 *       passed through without verification.</li>
 *   <li>{@code DORA_32_AUDIT_MISSING} — the payment-network operator holds
 *       no signature artefacts for this transaction reference. A serial
 *       declared in pacs.008 RgltryRptg does not substitute for them.</li>
 *   <li>{@code DECLARED_CERT_MISMATCH} — the serial declared in pacs.008
 *       RgltryRptg differs from the payment-network operator's; the
 *       gatekeeper is not called.</li>
 *   <li>{@code CERT_NOT_FOUND} — cert serial does not match any
 *       gatekeeper audit entry; either circumvented issuance or wrong
 *       cert.</li>
 *   <li>{@code SIGNATURE_INVALID} — cryptographic verification failed.</li>
 *   <li>{@code CERT_NON_COMPLIANT} — cert exists but did not pass
 *       structural-independence checks at issuance.</li>
 *   <li>{@code CERT_EXPIRED} — the signature verifies, but the certificate
 *       is outside its validity period (gatekeeper 1.6.0).</li>
 *   <li>{@code CERT_SUPERSEDED} / {@code CERT_REVOKED} /
 *       {@code CERT_DECOMMISSIONED} — the signature verifies, but the
 *       certificate's key was rotated, revoked or decommissioned by a
 *       key-lifecycle event on the gatekeeper.</li>
 *   <li>{@code MALFORMED_INPUT} / {@code ALGORITHM_NOT_SUPPORTED} — the
 *       gatekeeper could not evaluate the request; not a signature
 *       failure.</li>
 *   <li>{@code INVALID_SIGNATURE_MATERIAL} — the payment-network operator's
 *       artefacts are malformed; the gatekeeper is not called.</li>
 *   <li>{@code NETWORK_ERROR} — gatekeeper unreachable, timed out or
 *       returned an unusable body; or, in {@code http} payment-network mode,
 *       the payment-network operator unreachable, timed out or answering
 *       with a status other than 200 or 404. Default-deny applies.</li>
 *   <li>{@code OPERATOR_SIGNATURE_INVALID} — {@code http} payment-network
 *       mode only: the operator answered 200, but the answer is not
 *       well-formed {@code PayoutArtefacts}, its {@code op1} signature does
 *       not verify under a trusted operator certificate selected by
 *       {@code operatorKeyFingerprintHex}, its algorithm is not on the
 *       allow-list, or its {@code transactionReference} is not the one
 *       requested. The gatekeeper is not called.</li>
 *   <li>{@code REFERENCE_ALREADY_SETTLED} — the transaction reference, or the
 *       operator's payout instruction id, has already been allowed by
 *       railgate (or another evaluation holding it is still in progress).
 *       The gatekeeper is not called.</li>
 *   <li>{@code VERDICT_SIGNATURE_INVALID} — the gatekeeper's verdict is
 *       unsigned while {@code railgate.gatekeeper.require-signed-verdict} is
 *       true, or its {@code sv1} signature, key, algorithm or echoed request
 *       fields fail verification.</li>
 *   <li>{@code VERDICT_STALE} — the verdict's signature verifies, but its
 *       {@code verifiedAt} is further from railgate's clock than
 *       {@code railgate.gatekeeper.verdict-max-skew}.</li>
 *   <li>{@code INVALID_REQUEST} / {@code INTERNAL_ERROR} — produced by
 *       {@code SettlementExceptionHandler}. {@code INTERNAL_ERROR} is also
 *       produced by the orchestrator when an allowed settlement cannot be
 *       written to the replay journal.</li>
 * </ul>
 *
 * <p>{@code verdictSignature} records what railgate established about the
 * gatekeeper verdict's signature ({@code VERIFIED}, {@code UNSIGNED}, {@code UNVERIFIED},
 * {@code INVALID}); it is {@code null} when no verdict was consumed.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SettlementDecision {

    private boolean allow;

    private String reasonCode;

    private String message;

    private String transactionReference;

    private String auditEntryId;

    private String auditEntryHashHex;

    private VerdictSignatureStatus verdictSignature;
}
