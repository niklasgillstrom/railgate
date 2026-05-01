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
 *   <li>{@code DORA_32_AUDIT_MISSING} — no cert serial available; bank
 *       must populate pacs.008 RgltryRptg or the payment-network operator
 *       must expose the signature for this transaction.</li>
 *   <li>{@code CERT_NOT_FOUND} — cert serial does not match any
 *       gatekeeper audit entry; either circumvented issuance or wrong
 *       cert.</li>
 *   <li>{@code SIGNATURE_INVALID} — cryptographic verification failed.</li>
 *   <li>{@code CERT_NON_COMPLIANT} — cert exists but did not pass
 *       structural-independence checks at issuance.</li>
 *   <li>{@code NETWORK_ERROR} — gatekeeper or payment-network operator
 *       unreachable; default-deny applies.</li>
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
}
