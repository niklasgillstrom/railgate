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
 *   <li>{@code MALFORMED_INPUT} / {@code ALGORITHM_NOT_SUPPORTED} — the
 *       gatekeeper could not evaluate the request; not a signature
 *       failure.</li>
 *   <li>{@code INVALID_SIGNATURE_MATERIAL} — the payment-network operator's
 *       artefacts are malformed; the gatekeeper is not called.</li>
 *   <li>{@code NETWORK_ERROR} — gatekeeper unreachable, timed out or
 *       returned an unusable body; default-deny applies.</li>
 *   <li>{@code INVALID_REQUEST} / {@code INTERNAL_ERROR} — produced by
 *       {@code SettlementExceptionHandler}.</li>
 * </ul>
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
}
