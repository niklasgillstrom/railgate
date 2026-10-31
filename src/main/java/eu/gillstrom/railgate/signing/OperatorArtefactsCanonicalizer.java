package eu.gillstrom.railgate.signing;

import java.nio.charset.StandardCharsets;

/**
 * Canonical form {@code op1}: the bytes the payment-network operator signs
 * when it answers {@code GET /v1/payout-artefacts/{transactionReference}}
 * (specified in {@code api/payment-network-operator.openapi.yaml}).
 *
 * <pre>
 * "op1|" + transactionReference + "|" + payoutInstructionId + "|" + certSerialHex
 *        + "|" + issuerDn + "|" + digestHex + "|" + signatureBase64 + "|" + issuedAt
 * </pre>
 *
 * <p>encoded as UTF-8, where {@code certSerialHex}, {@code issuerDn} and
 * {@code digestHex} are normalised by {@link CanonicalFields}, and every one of
 * the seven fields is then passed through {@link CanonicalFields#escape}
 * ({@code '%'} to {@code "%25"} first, then {@code '|'} to {@code "%7C"}).
 * {@code issuedAt} and the other string fields are used exactly as the operator
 * sent them; railgate does not re-format them.</p>
 */
public final class OperatorArtefactsCanonicalizer {

    /** Version tag and first field of the canonical string. */
    public static final String VERSION = "op1";

    private OperatorArtefactsCanonicalizer() {
    }

    /**
     * @throws IllegalArgumentException when {@code certSerial} is not
     *     hexadecimal or {@code issuerDn} is not a distinguished name
     */
    public static String canonicalString(
            String transactionReference,
            String payoutInstructionId,
            String certSerial,
            String issuerDn,
            String digestHex,
            String signatureBase64,
            String issuedAt) {
        return VERSION
                + CanonicalFields.SEPARATOR + CanonicalFields.escape(transactionReference)
                + CanonicalFields.SEPARATOR + CanonicalFields.escape(payoutInstructionId)
                + CanonicalFields.SEPARATOR + CanonicalFields.escape(CanonicalFields.certSerialHex(certSerial))
                + CanonicalFields.SEPARATOR + CanonicalFields.escape(CanonicalFields.issuerDn(issuerDn))
                + CanonicalFields.SEPARATOR + CanonicalFields.escape(CanonicalFields.digestHex(digestHex))
                + CanonicalFields.SEPARATOR + CanonicalFields.escape(signatureBase64)
                + CanonicalFields.SEPARATOR + CanonicalFields.escape(issuedAt);
    }

    /** {@link #canonicalString} as UTF-8 bytes: what the signature covers. */
    public static byte[] canonicalBytes(
            String transactionReference,
            String payoutInstructionId,
            String certSerial,
            String issuerDn,
            String digestHex,
            String signatureBase64,
            String issuedAt) {
        return canonicalString(transactionReference, payoutInstructionId, certSerial, issuerDn,
                digestHex, signatureBase64, issuedAt).getBytes(StandardCharsets.UTF_8);
    }
}
