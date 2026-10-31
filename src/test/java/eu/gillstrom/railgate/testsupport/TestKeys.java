package eu.gillstrom.railgate.testsupport;

import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Test-only signing material under {@code src/test/resources}. None of it is
 * a secret; every key was generated for these tests.
 *
 * <ul>
 *   <li>{@code signing/operator-*.pem} — RSA 2048, the reference operator's key;</li>
 *   <li>{@code signing/gatekeeper-*.pem} — EC P-256, the gatekeeper's verdict key;</li>
 *   <li>{@code tls/test-*.pem} — RSA 2048, the listener test certificate,
 *       used here as a key nobody trusts.</li>
 * </ul>
 */
public final class TestKeys {

    public static final String OPERATOR_CERT = "signing/operator-cert.pem";
    public static final String OPERATOR_KEY = "signing/operator-key.pem";
    public static final String GATEKEEPER_CERT = "signing/gatekeeper-cert.pem";
    public static final String GATEKEEPER_KEY = "signing/gatekeeper-key.pem";
    public static final String UNTRUSTED_CERT = "tls/test-cert.pem";
    public static final String UNTRUSTED_KEY = "tls/test-key.pem";

    private TestKeys() {
    }

    public static X509Certificate certificate(String classpathLocation) {
        try (InputStream in = new ClassPathResource(classpathLocation).getInputStream()) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static PrivateKey privateKey(String classpathLocation) {
        try (InputStream in = new ClassPathResource(classpathLocation).getInputStream()) {
            String pem = new String(in.readAllBytes(), StandardCharsets.US_ASCII);
            String body = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body));
            for (String algorithm : new String[] {"RSA", "EC"}) {
                try {
                    return KeyFactory.getInstance(algorithm).generatePrivate(spec);
                } catch (GeneralSecurityException ignored) {
                    // try the next key type
                }
            }
            throw new IllegalStateException("not an RSA or EC PKCS#8 key: " + classpathLocation);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String signBase64(String algorithm, PrivateKey key, byte[] data) {
        try {
            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(key);
            signature.update(data);
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
