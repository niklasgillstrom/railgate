package eu.gillstrom.railgate.model;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Cryptographic artefacts retrieved from the payment-network operator
 * (Getswish AB in the Swedish reference deployment) for a given transaction.
 *
 * <p>Note that this carries only the digest, not the original transaction
 * payload. The verifier (gatekeeper) does not need to see transaction content;
 * SHA-512 collision resistance ensures that a valid signature over the digest
 * uniquely binds the signature to the exact transaction that was performed.
 *
 * <p>This shape is what {@code PaymentNetworkClient} returns and what
 * {@code GatekeeperClient} forwards to gatekeeper for verification.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PaymentSignature {

    /**
     * Hex-encoded SHA-512 digest of the original signed transaction payload.
     * Computed by the originating signer (customer's HSM-bound key) and
     * stored by the payment-network operator. Never recomputed from a
     * payload at this layer — the digest is the only data railgate ever
     * sees.
     */
    @NotBlank
    private String digestHex;

    /**
     * Base64-encoded RSA signature over the digest, produced by the
     * customer's HSM-bound private key (RSA-4096 with PKCS#1 v1.5 or
     * RSA-PSS padding, SHA-512 hash).
     */
    @NotBlank
    private String signatureBase64;

    /**
     * Decimal serial number of the signing certificate. Together with the
     * issuer DN this uniquely identifies the certificate in the gatekeeper
     * audit log.
     */
    @NotBlank
    private String certSerial;

    /**
     * Distinguished Name of the certificate issuer. Required because
     * certificate serial numbers are unique only within an issuer's namespace.
     */
    @NotBlank
    private String issuerDn;
}
