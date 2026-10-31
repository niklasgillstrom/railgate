package eu.gillstrom.railgate.signing;

import eu.gillstrom.railgate.model.PaymentSignature;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.util.Locale;

/**
 * Field normalisation shared by the two canonical forms railgate verifies
 * signatures over: {@code op1} (payment-network operator artefacts,
 * {@link OperatorArtefactsCanonicalizer}) and {@code sv1} (gatekeeper
 * verdicts, {@link VerdictCanonicalizer}).
 *
 * <p>Both the signer and railgate must produce the same bytes from the same
 * values. Every rule here is therefore part of the wire contract, and a change
 * to any of them is a new canonical-form version, not a fix.</p>
 *
 * <ul>
 *   <li>{@link #certSerialHex}: {@code new BigInteger(serial without an
 *       optional 0x or 0X prefix, 16).toString(16)} — lowercase, no leading
 *       zeros, {@code "0"} for zero.</li>
 *   <li>{@link #issuerDn}: {@code new X500Principal(dn).getName(X500Principal.RFC2253)}.</li>
 *   <li>{@link #digestHex}: lowercased ({@link Locale#ROOT}).</li>
 *   <li>{@link #escape}: {@code '%'} becomes {@code "%25"} first, then
 *       {@code '|'} becomes {@code "%7C"}.</li>
 * </ul>
 *
 * <p>A {@code null} value is written as the empty string by every method.</p>
 */
public final class CanonicalFields {

    /** Field separator of both canonical forms. */
    public static final char SEPARATOR = '|';

    private CanonicalFields() {
    }

    /**
     * Canonical hexadecimal certificate serial.
     *
     * @throws IllegalArgumentException when the value is not a hexadecimal
     *     serial in the form {@link PaymentSignature#parseCertSerial} accepts
     *     (hex digits only, optional {@code 0x}/{@code 0X} prefix, at most
     *     {@link PaymentSignature#MAX_CERT_SERIAL_LENGTH} characters). A sign,
     *     whitespace or separator characters are rejected rather than
     *     normalised, so that no two distinct inputs that a signer could
     *     reasonably have meant differently collapse to the same string.
     */
    public static String certSerialHex(String certSerial) {
        if (certSerial == null) {
            return "";
        }
        BigInteger serial = PaymentSignature.parseCertSerial(certSerial);
        if (serial == null) {
            throw new IllegalArgumentException("certSerial is not a hexadecimal serial");
        }
        return serial.toString(16);
    }

    /**
     * Canonical issuer DN: the RFC 2253 rendering of the parsed
     * {@link X500Principal}.
     *
     * @throws IllegalArgumentException when the value is not a distinguished
     *     name {@link X500Principal} can parse
     */
    public static String issuerDn(String issuerDn) {
        if (issuerDn == null) {
            return "";
        }
        return new X500Principal(issuerDn).getName(X500Principal.RFC2253);
    }

    /** Lowercased digest. No other check is made here. */
    public static String digestHex(String digestHex) {
        return digestHex == null ? "" : digestHex.toLowerCase(Locale.ROOT);
    }

    /**
     * Percent-encodes the two characters that would otherwise make the
     * canonical string ambiguous: {@code '%'} as {@code "%25"} (first), then
     * {@code '|'} as {@code "%7C"}. Nothing else is changed.
     */
    public static String escape(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("%", "%25").replace("|", "%7C");
    }

    /** {@code "true"} or {@code "false"}. */
    public static String bool(boolean value) {
        return value ? "true" : "false";
    }
}
