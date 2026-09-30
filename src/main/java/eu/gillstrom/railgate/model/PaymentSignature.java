package eu.gillstrom.railgate.model;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigInteger;
import java.util.regex.Pattern;

/**
 * Cryptographic artefacts retrieved from the payment-network operator
 * (Getswish AB in the Swedish reference deployment) for a given transaction.
 *
 * <p>Note that this carries only the digest, not the original transaction
 * payload. The verifier (gatekeeper) does not need to see transaction content.
 *
 * <p>The digest is supplied by the payment-network operator and is never
 * recomputed here — {@code SettlementRequest} carries what RIX-INST delivers,
 * which does not include the fields the signature was made over. A valid
 * signature therefore binds to the payload the digest was taken over, not to
 * the pacs.008 message being settled. See {@code README.md} for the residual
 * assumption this leaves and what would close it.
 *
 * <p>This shape is what {@code PaymentNetworkClient} returns and what
 * {@code GatekeeperClient} forwards to gatekeeper for verification.
 *
 * <p><b>Wire format.</b> The four fields are forwarded unchanged as the JSON
 * properties {@code certSerial}, {@code issuerDn}, {@code digestHex} and
 * {@code signatureBase64} of gatekeeper's {@code SignatureVerificationRequest}.
 * From gatekeeper 1.5.0 the gatekeeper resolves the signing certificate from
 * {@code (certSerial, issuerDn)} alone, so both identifiers must be in the
 * agreed form: {@code certSerial} hexadecimal, {@code issuerDn} an RFC 4514
 * string. Each field must also be non-blank and within gatekeeper's
 * {@code @Size} limits: {@code certSerial} at most 128 characters,
 * {@code issuerDn} at most 512, {@code digestHex} at most 256 and
 * {@code signatureBase64} at most 4096. {@code GatekeeperClient} checks all of
 * this before the call and answers {@code INVALID_SIGNATURE_MATERIAL} rather
 * than forwarding a request the gatekeeper would reject.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PaymentSignature {

    public static final int MAX_CERT_SERIAL_LENGTH = 128;

    private static final Pattern CERT_SERIAL_HEX = Pattern.compile("^(0[xX])?[0-9a-fA-F]+$");

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
     * customer's HSM-bound private key: RSA PKCS#1 v1.5 with SHA-512, the
     * Swish Utbetalning signing scheme and gatekeeper's default algorithm
     * {@code SHA512withRSA}.
     */
    @NotBlank
    private String signatureBase64;

    /**
     * Serial number of the signing certificate, in hexadecimal:
     * case-insensitive, with an optional {@code 0x} prefix, at most
     * {@link #MAX_CERT_SERIAL_LENGTH} characters. The gatekeeper compares it
     * numerically, so {@code 0x00C0FFEE} and {@code c0ffee} name the same
     * certificate. A decimal rendering must not be supplied: a string of
     * decimal digits is also valid hexadecimal, so it is not rejected, but it
     * is read as a different number. Together with the issuer DN this uniquely
     * identifies the certificate in the gatekeeper audit log.
     */
    @NotBlank
    private String certSerial;

    /**
     * Distinguished Name of the certificate issuer, as an RFC 4514 string
     * (for example {@code CN=Example CA,O=Example Bank,C=SE}). The gatekeeper
     * compares it by {@code X500Principal} equality, so attribute spacing and
     * case differences that X.500 name comparison ignores do not matter.
     * Required because certificate serial numbers are unique only within an
     * issuer's namespace.
     */
    @NotBlank
    private String issuerDn;

    public static BigInteger parseCertSerial(String certSerial) {
        if (certSerial == null
                || certSerial.length() > MAX_CERT_SERIAL_LENGTH
                || !CERT_SERIAL_HEX.matcher(certSerial).matches()) {
            return null;
        }
        String digits = certSerial.startsWith("0x") || certSerial.startsWith("0X")
                ? certSerial.substring(2)
                : certSerial;
        return new BigInteger(digits, 16);
    }
}
