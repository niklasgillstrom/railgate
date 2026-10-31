package eu.gillstrom.railgate.signing;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the {@code op1} canonical form against the example in
 * {@code api/payment-network-operator.openapi.yaml}.
 */
class OperatorArtefactsCanonicalizerTest {

    @Test
    void goldenExampleFromTheOperatorSpecification() throws Exception {
        String canonical = OperatorArtefactsCanonicalizer.canonicalString(
                "E2E|ID%01",
                "E4D773858AF5459B96ABCA4B9DBFF94D",
                "0x00C0FFEE",
                "CN=Example CA, O=Example Bank, C=SE",
                "AB".repeat(64),
                "c2lnbmF0dXJl",
                "2026-10-30T12:00:00Z");

        String expected = "op1|E2E%7CID%2501|E4D773858AF5459B96ABCA4B9DBFF94D|c0ffee|"
                + "CN=Example CA,O=Example Bank,C=SE|" + "ab".repeat(64)
                + "|c2lnbmF0dXJl|2026-10-30T12:00:00Z";
        assertThat(canonical).isEqualTo(expected);

        byte[] bytes = OperatorArtefactsCanonicalizer.canonicalBytes(
                "E2E|ID%01", "E4D773858AF5459B96ABCA4B9DBFF94D", "0x00C0FFEE",
                "CN=Example CA, O=Example Bank, C=SE", "AB".repeat(64), "c2lnbmF0dXJl", "2026-10-30T12:00:00Z");
        assertThat(bytes).isEqualTo(expected.getBytes(StandardCharsets.UTF_8)).hasSize(254);
        assertThat(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)))
                .isEqualTo("4a6ac4f4b5f085aaa27d79539d073cece820ae854d17bcb85b77133f545b038d");
    }

    @Test
    void everyStringFieldIsEscapedPercentFirst() {
        // "%7C" in the input must become "%257C", not "|" or "%7C".
        String canonical = OperatorArtefactsCanonicalizer.canonicalString(
                "%7C", "a|b", "ff", "CN=x|y", "", "s%", "2026|");

        assertThat(canonical).isEqualTo("op1|%257C|a%7Cb|ff|CN=x%7Cy||s%25|2026%7C");
    }

    @Test
    void equivalentSerialsAndIssuerSpellingsGiveTheSameBytes() {
        String a = OperatorArtefactsCanonicalizer.canonicalString("r", "p", "0X000ABC", "CN=I, O=B, C=SE", "AA", "s", "t");
        String b = OperatorArtefactsCanonicalizer.canonicalString("r", "p", "abc", "CN=I,O=B,C=SE", "aa", "s", "t");

        assertThat(a).isEqualTo(b).isEqualTo("op1|r|p|abc|CN=I,O=B,C=SE|aa|s|t");
    }
}
