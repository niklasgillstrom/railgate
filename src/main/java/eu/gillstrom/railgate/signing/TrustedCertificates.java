package eu.gillstrom.railgate.signing;

import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * A pinned set of signing certificates, indexed by key fingerprint.
 *
 * <p>The fingerprint is the one the gatekeeper publishes for its signing keys
 * on {@code GET /v1/gatekeeper/keys} ({@code publicKeyFingerprintHex}) and
 * puts in its verdicts ({@code signingKeyFingerprintHex}): SHA-256 over the
 * DER encoding of the certificate's SubjectPublicKeyInfo, i.e. the bytes of
 * {@code certificate.getPublicKey().getEncoded()}, rendered as lowercase
 * hexadecimal, 64 characters, no separators. It is not the SHA-256 of the
 * certificate's DER encoding. The same convention is used for the
 * payment-network operator's {@code operatorKeyFingerprintHex}, so that a
 * relying party uses one fingerprint for a signing key everywhere.</p>
 *
 * <p>A signed statement names the key it was signed with by that fingerprint;
 * the fingerprint only selects the certificate, and the signature must then
 * verify under its public key. Because the fingerprint identifies the key,
 * two certificates for the same key have the same fingerprint; the first one
 * read is kept, and either verifies exactly the same signatures.</p>
 *
 * <p>Trust comes from configuration alone. The certificates are not chained
 * to a CA, and neither their validity period nor their revocation status is
 * checked: removing a certificate from the file and restarting is how one is
 * withdrawn.</p>
 */
public final class TrustedCertificates {

    private static final TrustedCertificates NONE = new TrustedCertificates(Map.of());

    private final Map<String, X509Certificate> byFingerprint;

    private TrustedCertificates(Map<String, X509Certificate> byFingerprint) {
        this.byFingerprint = Collections.unmodifiableMap(byFingerprint);
    }

    /** No trusted certificate: every signed statement fails to verify. */
    public static TrustedCertificates none() {
        return NONE;
    }

    /** The given certificates, de-duplicated by fingerprint. */
    public static TrustedCertificates of(Collection<X509Certificate> certificates) {
        Map<String, X509Certificate> map = new LinkedHashMap<>();
        for (X509Certificate certificate : certificates) {
            map.putIfAbsent(fingerprintHex(certificate), certificate);
        }
        return new TrustedCertificates(map);
    }

    /**
     * Loads every certificate in a PEM file (one or more
     * {@code -----BEGIN CERTIFICATE-----} blocks).
     *
     * @param location {@code classpath:<path>}, {@code file:<path>} or a plain
     *     file-system path
     * @param property the configuration property the location came from, for
     *     the error message
     * @throws IllegalStateException when the location cannot be read, is not
     *     PEM/DER X.509, or holds no certificate
     */
    public static TrustedCertificates load(String location, String property) {
        String trimmed = location == null ? "" : location.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalStateException(property + " is empty");
        }
        try (InputStream in = open(trimmed)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certificates = factory.generateCertificates(in);
            Map<String, X509Certificate> map = new LinkedHashMap<>();
            for (Certificate certificate : certificates) {
                if (certificate instanceof X509Certificate x509) {
                    map.putIfAbsent(fingerprintHex(x509), x509);
                }
            }
            if (map.isEmpty()) {
                throw new IllegalStateException(property + " (" + trimmed + ") holds no X.509 certificate");
            }
            return new TrustedCertificates(map);
        } catch (IOException | CertificateException e) {
            throw new IllegalStateException(property + " (" + trimmed + ") could not be read as PEM "
                    + "certificates: " + e.getClass().getSimpleName(), e);
        }
    }

    private static InputStream open(String location) throws IOException {
        if (location.startsWith("classpath:")) {
            return new ClassPathResource(location.substring("classpath:".length())).getInputStream();
        }
        String path = location.startsWith("file:") ? location.substring("file:".length()) : location;
        return Files.newInputStream(Path.of(path));
    }

    /** The certificate whose fingerprint is exactly {@code fingerprintHex}. */
    public Optional<X509Certificate> byFingerprint(String fingerprintHex) {
        if (fingerprintHex == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(byFingerprint.get(fingerprintHex));
    }

    public boolean isEmpty() {
        return byFingerprint.isEmpty();
    }

    /** The fingerprints held, in file order. */
    public Set<String> fingerprints() {
        return byFingerprint.keySet();
    }

    /**
     * Lowercase hex SHA-256 of the DER SubjectPublicKeyInfo of the
     * certificate's public key ({@code getPublicKey().getEncoded()}), no
     * separators: the gatekeeper's {@code GET /v1/gatekeeper/keys}
     * {@code publicKeyFingerprintHex} convention.
     */
    public static String fingerprintHex(X509Certificate certificate) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(certificate.getPublicKey().getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
