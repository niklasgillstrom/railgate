package eu.gillstrom.railgate.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Result returned by gatekeeper for a verification request.
 *
 * <p>{@code signatureValid} reports whether the cryptographic signature
 * verified against the certificate's public key. {@code compliant} reports
 * whether the certificate corresponds to a gatekeeper audit entry that
 * passed structural-independence and HSM-attestation checks at issuance time.
 *
 * <p>Both must be true for railgate to allow settlement. Any false value
 * triggers default-deny.
 *
 * <p>{@code auditEntryId} is the gatekeeper audit-log entry identifier
 * (when found), retained for cross-referencing during forensic
 * investigations. {@code reason} is a structured error code when the result
 * is non-positive (e.g. {@code CERT_NOT_FOUND}, {@code SIGNATURE_INVALID},
 * {@code CERT_NON_COMPLIANT}).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VerificationResult {

    private boolean signatureValid;

    private boolean compliant;

    private String auditEntryId;

    private String reason;

    /** Convenience: whether settlement should be allowed. */
    public boolean isAllowed() {
        return signatureValid && compliant;
    }
}
