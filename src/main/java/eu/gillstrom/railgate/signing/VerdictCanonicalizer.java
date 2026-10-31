package eu.gillstrom.railgate.signing;

import java.nio.charset.StandardCharsets;

/**
 * Canonical form {@code sv1}: the bytes the gatekeeper signs over its
 * {@code POST /api/v1/verify} verdict.
 *
 * <pre>
 * "sv1|" + verifiedAt + "|" + certSerialHex + "|" + issuerDn + "|" + digestHex
 *        + "|" + signatureValid + "|" + compliant + "|" + reason
 *        + "|" + auditEntryId + "|" + auditEntryHashHex
 * </pre>
 *
 * <p>encoded as UTF-8, where</p>
 * <ul>
 *   <li>{@code certSerialHex}, {@code issuerDn} and {@code digestHex} are
 *       normalised by {@link CanonicalFields} (hex serial without prefix or
 *       leading zeros, RFC 2253 DN, lowercased digest);</li>
 *   <li>{@code signatureValid} and {@code compliant} are {@code "true"} or
 *       {@code "false"};</li>
 *   <li>a {@code null} string is written as {@code ""};</li>
 *   <li>{@code verifiedAt}, {@code issuerDn}, {@code reason},
 *       {@code auditEntryId} and {@code auditEntryHashHex} are passed through
 *       {@link CanonicalFields#escape} ({@code '%'} to {@code "%25"} first, then
 *       {@code '|'} to {@code "%7C"}). {@code certSerialHex} and
 *       {@code digestHex} are not escaped.</li>
 * </ul>
 *
 * <p>{@code verifiedAt} is used exactly as the gatekeeper sent it (the
 * gatekeeper writes it with {@code Instant.toString()}); railgate does not
 * re-format it before building this string.</p>
 *
 * <p>Pinned by {@code VerdictCanonicalizerTest}; the gatekeeper's signer must
 * reproduce the same golden value.</p>
 */
public final class VerdictCanonicalizer {

    /** Version tag and first field of the canonical string. */
    public static final String VERSION = "sv1";

    private VerdictCanonicalizer() {
    }

    /**
     * @throws IllegalArgumentException when {@code certSerial} is not
     *     hexadecimal or {@code issuerDn} is not a distinguished name
     */
    public static String canonicalString(
            String verifiedAt,
            String certSerial,
            String issuerDn,
            String digestHex,
            boolean signatureValid,
            boolean compliant,
            String reason,
            String auditEntryId,
            String auditEntryHashHex) {
        return VERSION
                + CanonicalFields.SEPARATOR + CanonicalFields.escape(verifiedAt)
                + CanonicalFields.SEPARATOR + CanonicalFields.certSerialHex(certSerial)
                + CanonicalFields.SEPARATOR + CanonicalFields.escape(CanonicalFields.issuerDn(issuerDn))
                + CanonicalFields.SEPARATOR + CanonicalFields.digestHex(digestHex)
                + CanonicalFields.SEPARATOR + CanonicalFields.bool(signatureValid)
                + CanonicalFields.SEPARATOR + CanonicalFields.bool(compliant)
                + CanonicalFields.SEPARATOR + CanonicalFields.escape(reason)
                + CanonicalFields.SEPARATOR + CanonicalFields.escape(auditEntryId)
                + CanonicalFields.SEPARATOR + CanonicalFields.escape(auditEntryHashHex);
    }

    /** {@link #canonicalString} as UTF-8 bytes: what the signature covers. */
    public static byte[] canonicalBytes(
            String verifiedAt,
            String certSerial,
            String issuerDn,
            String digestHex,
            boolean signatureValid,
            boolean compliant,
            String reason,
            String auditEntryId,
            String auditEntryHashHex) {
        return canonicalString(verifiedAt, certSerial, issuerDn, digestHex, signatureValid, compliant,
                reason, auditEntryId, auditEntryHashHex).getBytes(StandardCharsets.UTF_8);
    }
}
