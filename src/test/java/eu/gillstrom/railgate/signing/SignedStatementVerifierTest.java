package eu.gillstrom.railgate.signing;

import eu.gillstrom.railgate.testsupport.TestKeys;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.List;

import static eu.gillstrom.railgate.signing.SignedStatementVerifier.Outcome.MALFORMED_SIGNATURE;
import static eu.gillstrom.railgate.signing.SignedStatementVerifier.Outcome.SIGNATURE_MISMATCH;
import static eu.gillstrom.railgate.signing.SignedStatementVerifier.Outcome.VALID;
import static org.assertj.core.api.Assertions.assertThat;

/** The checks {@link SignedStatementVerifier} makes on the signature value before it verifies it. */
class SignedStatementVerifierTest {

    private static final X509Certificate CERTIFICATE = TestKeys.certificate(TestKeys.OPERATOR_CERT);
    private static final TrustedCertificates TRUSTED = TrustedCertificates.of(List.of(CERTIFICATE));
    private static final byte[] DATA = "canonical bytes".getBytes(StandardCharsets.US_ASCII);

    private static SignedStatementVerifier.Outcome verify(String signatureBase64) {
        return SignedStatementVerifier.verify(TRUSTED, TrustedCertificates.fingerprintHex(CERTIFICATE),
                "SHA256withRSA", signatureBase64, DATA);
    }

    @Test
    void aSignatureByTheTrustedKeyVerifies() {
        assertThat(verify(TestKeys.signBase64("SHA256withRSA", TestKeys.privateKey(TestKeys.OPERATOR_KEY), DATA)))
                .isEqualTo(VALID);
    }

    @Test
    void anAbsentEmptyOrOverlongSignatureIsMalformed() {
        assertThat(verify(null)).isEqualTo(MALFORMED_SIGNATURE);
        assertThat(verify("")).isEqualTo(MALFORMED_SIGNATURE);

        String atLimit = "A".repeat(SignedStatementVerifier.MAX_SIGNATURE_BASE64_LENGTH);
        assertThat(verify(atLimit)).as("at the limit it is decoded and checked").isEqualTo(SIGNATURE_MISMATCH);
        assertThat(verify(atLimit + "A")).isEqualTo(MALFORMED_SIGNATURE);
    }

    @Test
    void aSignatureThatIsNotBase64IsMalformed() {
        assertThat(verify("not base64!")).isEqualTo(MALFORMED_SIGNATURE);
    }
}
