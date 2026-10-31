package eu.gillstrom.railgate.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
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
 * <p>{@code auditEntryId} is the gatekeeper's approval-registry
 * {@code verificationId} the compliance verdict was read from (when found);
 * it is shared by every settlement against the same certificate.
 * {@code auditEntryHashHex} is the {@code thisEntryHashHex} of the
 * {@code SETTLEMENT_VERIFY} audit entry the gatekeeper wrote for this call
 * (gatekeeper 1.5.0 and later). Both are retained for cross-referencing
 * during forensic investigations. {@code reason} is a structured error code when the result
 * is non-positive (e.g. {@code CERT_NOT_FOUND}, {@code SIGNATURE_INVALID},
 * {@code CERT_NON_COMPLIANT}).
 *
 * <p><b>Signed verdict.</b> {@code verifiedAt}, {@code verdictSignatureBase64},
 * {@code verdictSignatureAlgorithm} and {@code signingKeyFingerprintHex} carry
 * the gatekeeper's signature over the {@code sv1} canonical form
 * ({@code VerdictCanonicalizer}); {@code GatekeeperClient} verifies it.
 * {@code certSerial}, {@code issuerDn} and {@code digestHex} are optional
 * echoes of the request: when the gatekeeper sends them they must match what
 * railgate sent, and the canonical form is built from railgate's own values
 * either way.
 *
 * <p>Unknown properties in the gatekeeper's response are ignored, so the
 * gatekeeper can add fields without breaking railgate.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class VerificationResult {

    private boolean signatureValid;

    private boolean compliant;

    private String auditEntryId;

    private String reason;

    private String auditEntryHashHex;

    /** ISO-8601 instant at which the gatekeeper produced the verdict ({@code Instant.toString()}). */
    private String verifiedAt;

    /** Base64 signature over the {@code sv1} canonical bytes. */
    private String verdictSignatureBase64;

    /** JCA name of the verdict signature algorithm, e.g. {@code SHA256withRSA}. */
    private String verdictSignatureAlgorithm;

    /**
     * Fingerprint of the gatekeeper's verdict signing key as published on its
     * {@code GET /v1/gatekeeper/keys} ({@code publicKeyFingerprintHex}):
     * lowercase hex SHA-256 of the DER SubjectPublicKeyInfo, no separators.
     */
    private String signingKeyFingerprintHex;

    /** Optional echo of the request's {@code certSerial}. */
    private String certSerial;

    /** Optional echo of the request's {@code issuerDn}. */
    private String issuerDn;

    /** Optional echo of the request's {@code digestHex}. */
    private String digestHex;

    /**
     * Set by {@code GatekeeperClient} after it has checked the verdict
     * signature; never read from the gatekeeper's JSON.
     */
    @JsonIgnore
    private VerdictSignatureStatus verdictSignature;

    /** Convenience: whether settlement should be allowed. */
    @JsonIgnore
    public boolean isAllowed() {
        return signatureValid && compliant;
    }

    /** Whether the gatekeeper sent any of the four signature fields. */
    @JsonIgnore
    public boolean hasAnySignatureField() {
        return verifiedAt != null || verdictSignatureBase64 != null
                || verdictSignatureAlgorithm != null || signingKeyFingerprintHex != null;
    }
}
