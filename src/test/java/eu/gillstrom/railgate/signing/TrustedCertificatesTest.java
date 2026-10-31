package eu.gillstrom.railgate.signing;

import eu.gillstrom.railgate.testsupport.TestKeys;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.ClassPathResource;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TrustedCertificatesTest {

    /**
     * The key fingerprint, computed independently with OpenSSL:
     * {@code openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum}
     * (SHA-256 of the DER SubjectPublicKeyInfo, lowercase hex).
     */
    private static final String OPERATOR_FINGERPRINT = "345f117f9e4af2d32ccc66d4f7a6a92631f15afa657a8ee28dcc4bcc7230e878";
    private static final String GATEKEEPER_FINGERPRINT = "90c3bfc9e07a6ba10a166140b32b98effc7d6aab6de6e6f37cf3507a614046d8";
    /** {@code openssl x509 -outform DER | sha256sum}: the certificate hash, which is NOT the fingerprint. */
    private static final String OPERATOR_CERTIFICATE_DER_SHA256 =
            "a60f8ad2fe7bef00a5bc12ca70454d69270c7957376589911010a949837ca274";
    private static final String GATEKEEPER_CERTIFICATE_DER_SHA256 =
            "512df98f330ad29f29f6af4a5b723e044602297f07492603568bb10cc6a994c1";
    /** Another certificate (other subject, serial and validity) for the gatekeeper test key. */
    private static final String GATEKEEPER_CERT_REISSUED = "signing/gatekeeper-cert-reissued.pem";

    @TempDir
    Path tempDir;

    @Test
    void theFingerprintIsTheLowercaseHexSha256OfTheSubjectPublicKeyInfoAsOnGatekeeperKeys() throws Exception {
        X509Certificate operator = TestKeys.certificate(TestKeys.OPERATOR_CERT);
        X509Certificate gatekeeper = TestKeys.certificate(TestKeys.GATEKEEPER_CERT);

        assertThat(TrustedCertificates.fingerprintHex(operator)).isEqualTo(OPERATOR_FINGERPRINT);
        assertThat(TrustedCertificates.fingerprintHex(gatekeeper)).isEqualTo(GATEKEEPER_FINGERPRINT)
                .matches("^[0-9a-f]{64}$");
        // Exactly what gatekeeper's GatekeeperKeyDirectory publishes as
        // publicKeyFingerprintHex: HexFormat.of() over SHA-256 of getPublicKey().getEncoded().
        assertThat(TrustedCertificates.fingerprintHex(gatekeeper)).isEqualTo(HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(gatekeeper.getPublicKey().getEncoded())));
        // Not the hash of the certificate.
        assertThat(OPERATOR_FINGERPRINT).isNotEqualTo(OPERATOR_CERTIFICATE_DER_SHA256);
        assertThat(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(operator.getEncoded())))
                .isEqualTo(OPERATOR_CERTIFICATE_DER_SHA256);
    }

    @Test
    void theFingerprintIdentifiesTheKeySoAReissuedCertificateHasTheSameOne() throws Exception {
        X509Certificate original = TestKeys.certificate(TestKeys.GATEKEEPER_CERT);
        X509Certificate reissued = TestKeys.certificate(GATEKEEPER_CERT_REISSUED);
        assertThat(reissued.getEncoded()).isNotEqualTo(original.getEncoded());

        assertThat(TrustedCertificates.fingerprintHex(reissued)).isEqualTo(GATEKEEPER_FINGERPRINT);

        Path pem = tempDir.resolve("both.pem");
        Files.writeString(pem, read(TestKeys.GATEKEEPER_CERT) + read(GATEKEEPER_CERT_REISSUED),
                StandardCharsets.US_ASCII);
        TrustedCertificates trusted = TrustedCertificates.load(pem.toString(), "p");
        assertThat(trusted.fingerprints()).containsExactly(GATEKEEPER_FINGERPRINT);
        assertThat(trusted.byFingerprint(GATEKEEPER_FINGERPRINT)).contains(original);
        assertThat(trusted.byFingerprint(GATEKEEPER_CERTIFICATE_DER_SHA256))
                .as("the certificate hash selects nothing").isEmpty();
    }

    @Test
    void aPemFileWithSeveralCertificatesTrustsEachOfThem() throws Exception {
        Path pem = tempDir.resolve("trusted.pem");
        Files.writeString(pem, read(TestKeys.OPERATOR_CERT) + read(TestKeys.GATEKEEPER_CERT)
                + read(TestKeys.OPERATOR_CERT), StandardCharsets.US_ASCII);

        TrustedCertificates trusted = TrustedCertificates.load(pem.toString(), "p");
        TrustedCertificates viaFilePrefix = TrustedCertificates.load("file:" + pem, "p");

        assertThat(trusted.fingerprints()).containsExactly(OPERATOR_FINGERPRINT, GATEKEEPER_FINGERPRINT);
        assertThat(viaFilePrefix.fingerprints()).containsExactly(OPERATOR_FINGERPRINT, GATEKEEPER_FINGERPRINT);
        assertThat(trusted.byFingerprint(GATEKEEPER_FINGERPRINT)).isPresent();
        assertThat(trusted.byFingerprint(GATEKEEPER_FINGERPRINT.toUpperCase()))
                .as("the fingerprint is matched exactly, lowercase").isEmpty();
        assertThat(TrustedCertificates.load("classpath:" + TestKeys.GATEKEEPER_CERT, "p").fingerprints())
                .containsExactly(GATEKEEPER_FINGERPRINT);
    }

    @Test
    void aMissingEmptyOrUnreadableFileIsAStartUpFailure() throws Exception {
        Path empty = Files.writeString(tempDir.resolve("empty.pem"), "");
        Path garbage = Files.writeString(tempDir.resolve("garbage.pem"),
                "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n");

        assertThatThrownBy(() -> TrustedCertificates.load(tempDir.resolve("absent.pem").toString(), "the.property"))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("the.property");
        assertThatThrownBy(() -> TrustedCertificates.load(empty.toString(), "the.property"))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("no X.509 certificate");
        assertThatThrownBy(() -> TrustedCertificates.load(garbage.toString(), "the.property"))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> TrustedCertificates.load(" ", "the.property"))
                .isInstanceOf(IllegalStateException.class);
    }

    private static String read(String classpathLocation) throws Exception {
        return new String(new ClassPathResource(classpathLocation).getInputStream().readAllBytes(),
                StandardCharsets.US_ASCII);
    }
}
