package eu.gillstrom.railgate.signing;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;

/**
 * Verifies a detached signature over canonical bytes under a pinned
 * certificate. Used for both the operator's {@code op1} artefacts and the
 * gatekeeper's {@code sv1} verdict.
 *
 * <p>Checks, in order: the fingerprint selects a certificate in the trusted
 * set; the algorithm is on {@link #ALLOWED_ALGORITHMS} (exact, case-sensitive
 * match); the signature is standard base64; the signature verifies over the
 * canonical bytes under the selected certificate's public key. The first
 * failure is returned and nothing after it is evaluated.</p>
 */
public final class SignedStatementVerifier {

    /**
     * JCA signature algorithms railgate accepts on a signed statement.
     * SHA-1 and unhashed ({@code NONEwith...}) schemes are excluded; RSASSA-PSS
     * is not listed because its parameters are not part of the wire format.
     */
    public static final Set<String> ALLOWED_ALGORITHMS = Set.of(
            "SHA256withRSA",
            "SHA384withRSA",
            "SHA512withRSA",
            "SHA256withECDSA",
            "SHA384withECDSA",
            "SHA512withECDSA",
            "Ed25519");

    /** Upper bound on the base64 signature accepted for decoding. */
    static final int MAX_SIGNATURE_BASE64_LENGTH = 4096;

    /** Outcome of one verification; {@link #VALID} is the only success. */
    public enum Outcome {
        VALID,
        UNKNOWN_KEY,
        ALGORITHM_NOT_ALLOWED,
        MALFORMED_SIGNATURE,
        SIGNATURE_MISMATCH;

        /** A short description for the operator's log; carries no input values. */
        public String describe() {
            return switch (this) {
                case VALID -> "signature verifies";
                case UNKNOWN_KEY -> "the key fingerprint matches no trusted certificate";
                case ALGORITHM_NOT_ALLOWED -> "the signature algorithm is not on the allow-list";
                case MALFORMED_SIGNATURE -> "the signature is missing, too long or not base64";
                case SIGNATURE_MISMATCH -> "the signature does not verify over the canonical bytes";
            };
        }
    }

    private SignedStatementVerifier() {
    }

    public static Outcome verify(
            TrustedCertificates trusted,
            String keyFingerprintHex,
            String algorithm,
            String signatureBase64,
            byte[] canonicalBytes) {
        Optional<X509Certificate> certificate = trusted.byFingerprint(keyFingerprintHex);
        if (certificate.isEmpty()) {
            return Outcome.UNKNOWN_KEY;
        }
        if (algorithm == null || !ALLOWED_ALGORITHMS.contains(algorithm)) {
            return Outcome.ALGORITHM_NOT_ALLOWED;
        }
        if (signatureBase64 == null || signatureBase64.isEmpty()
                || signatureBase64.length() > MAX_SIGNATURE_BASE64_LENGTH) {
            return Outcome.MALFORMED_SIGNATURE;
        }
        byte[] signatureBytes;
        try {
            signatureBytes = Base64.getDecoder().decode(signatureBase64);
        } catch (IllegalArgumentException e) {
            return Outcome.MALFORMED_SIGNATURE;
        }
        try {
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(certificate.get().getPublicKey());
            verifier.update(canonicalBytes);
            return verifier.verify(signatureBytes) ? Outcome.VALID : Outcome.SIGNATURE_MISMATCH;
        } catch (GeneralSecurityException | RuntimeException e) {
            // A key that does not fit the algorithm (an EC key named with
            // SHA256withRSA), or an encoding the provider rejects.
            return Outcome.SIGNATURE_MISMATCH;
        }
    }
}
