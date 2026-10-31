package eu.gillstrom.railgate.client;

import eu.gillstrom.railgate.model.PaymentSignature;
import eu.gillstrom.railgate.model.VerdictSignatureStatus;
import eu.gillstrom.railgate.model.VerificationResult;
import eu.gillstrom.railgate.signing.TrustedCertificates;
import eu.gillstrom.railgate.testsupport.TestKeys;
import eu.gillstrom.railgate.testsupport.VerdictSigner;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** {@link VerdictVerifier#check} on the request fields and on the echoes of them a signed verdict carries. */
class VerdictVerifierTest {

    private static final Instant NOW = Instant.parse("2026-10-30T12:00:00Z");
    private static final String SERIAL = "0x00C0FFEE";
    private static final String ISSUER = "CN=Example CA, O=Example Bank, C=SE";
    private static final String DIGEST = "c0de".repeat(32);

    private final VerdictVerifier verifier = new VerdictVerifier(
            TrustedCertificates.of(List.of(TestKeys.certificate(TestKeys.GATEKEEPER_CERT))), true,
            Duration.ofSeconds(60), Clock.fixed(NOW, ZoneOffset.UTC));

    private static PaymentSignature sent(String serial) {
        return PaymentSignature.builder().certSerial(serial).issuerDn(ISSUER).digestHex(DIGEST)
                .signatureBase64("c2lnbmF0dXJl").build();
    }

    /** A verdict signed over the sent values, without echoes. */
    private static VerificationResult signed() {
        VerdictSigner signer = new VerdictSigner(SERIAL, ISSUER, DIGEST);
        Map<String, Object> body = signer.body();
        return VerificationResult.builder()
                .signatureValid(signer.signatureValid)
                .compliant(signer.compliant)
                .auditEntryId(signer.auditEntryId)
                .reason(signer.reason)
                .auditEntryHashHex(signer.auditEntryHashHex)
                .verifiedAt(signer.verifiedAt)
                .verdictSignatureBase64((String) body.get("verdictSignatureBase64"))
                .verdictSignatureAlgorithm(signer.algorithm)
                .signingKeyFingerprintHex((String) body.get("signingKeyFingerprintHex"))
                .build();
    }

    @Test
    void echoesInAnotherSpellingOfTheSentValuesMatch() {
        VerificationResult verdict = signed();
        verdict.setCertSerial("c0ffee");
        verdict.setIssuerDn("CN=Example CA,O=Example Bank,C=SE");
        VerdictVerifier.Check check = verifier.check(sent(SERIAL), verdict);
        assertThat(check.status()).as(check.detail()).isEqualTo(VerdictSignatureStatus.VERIFIED);
    }

    @Test
    void anEchoOfAnotherValueOrOneThatDoesNotParseDoesNotMatch() {
        for (String serial : List.of("c0fffe", "not hex")) {
            VerificationResult verdict = signed();
            verdict.setCertSerial(serial);
            assertThat(verifier.check(sent(SERIAL), verdict).detail()).as(serial)
                    .isEqualTo("the echoed certSerial does not match the request");
        }
        for (String issuer : List.of("CN=Other CA,O=Example Bank,C=SE", "not a distinguished name")) {
            VerificationResult verdict = signed();
            verdict.setIssuerDn(issuer);
            assertThat(verifier.check(sent(SERIAL), verdict).detail()).as(issuer)
                    .isEqualTo("the echoed issuerDn does not match the request");
        }
    }

    @Test
    void requestFieldsThatCannotBeCanonicalisedMakeTheVerdictInvalid() {
        VerdictVerifier.Check check = verifier.check(sent("not hex"), signed());
        assertThat(check.status()).isEqualTo(VerdictSignatureStatus.INVALID);
        assertThat(check.reasonCode()).isEqualTo(VerdictVerifier.VERDICT_SIGNATURE_INVALID);
        assertThat(check.detail()).isEqualTo("the request fields cannot be canonicalised");
    }

    @Test
    void aBlankSignatureFieldCountsAsMissing() {
        List<java.util.function.Consumer<VerificationResult>> blanks = List.of(
                v -> v.setVerifiedAt(" "),
                v -> v.setVerdictSignatureBase64(" "),
                v -> v.setVerdictSignatureAlgorithm(" "),
                v -> v.setSigningKeyFingerprintHex(" "));
        for (int i = 0; i < blanks.size(); i++) {
            VerificationResult verdict = signed();
            blanks.get(i).accept(verdict);
            assertThat(verifier.check(sent(SERIAL), verdict).detail()).as("field " + i)
                    .isEqualTo("the verdict carries some but not all of the four signature fields");
        }
    }
}
