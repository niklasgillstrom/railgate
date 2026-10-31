package eu.gillstrom.railgate.signing;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Pins the {@code sv1} canonical form. The gatekeeper's signer must produce
 * the same bytes from the same inputs; the golden example below is shared with
 * the gatekeeper side.
 */
class VerdictCanonicalizerTest {

    /** The shared golden example (D4). */
    @Test
    void goldenExampleSharedWithTheGatekeeper() throws Exception {
        String canonical = VerdictCanonicalizer.canonicalString(
                "2026-10-30T12:00:00Z",
                "0x00C0FFEE",
                "CN=Example CA,O=Example Bank,C=SE",
                "AB".repeat(64),
                true,
                false,
                "A|B%C",
                "id-1",
                "a".repeat(64));

        String expected = "sv1|2026-10-30T12:00:00Z|c0ffee|CN=Example CA,O=Example Bank,C=SE|"
                + "ab".repeat(64) + "|true|false|A%7CB%25C|id-1|" + "a".repeat(64);
        assertThat(canonical).isEqualTo(expected);

        byte[] bytes = VerdictCanonicalizer.canonicalBytes(
                "2026-10-30T12:00:00Z", "0x00C0FFEE", "CN=Example CA,O=Example Bank,C=SE",
                "AB".repeat(64), true, false, "A|B%C", "id-1", "a".repeat(64));
        assertThat(bytes).isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
        assertThat(bytes).hasSize(285);
        assertThat(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)))
                .isEqualTo("a938ea6660899505b02ad6b212462ac9e9d61556695f89c1d3a4b3a8cb507e10");
    }

    @Test
    void nullStringsAreEmptyAndOnlyTheNamedFieldsAreEscaped() {
        String canonical = VerdictCanonicalizer.canonicalString(
                "2026|%", "0X0", "CN=a|b,O=x%y", "Ff".repeat(64), false, true, null, null, null);

        assertThat(canonical).isEqualTo("sv1|2026%7C%25|0|CN=a%7Cb,O=x%25y|" + "ff".repeat(64)
                + "|false|true|||");
    }

    @Test
    void theIssuerIsWrittenInRfc2253FormAndTextAsUtf8() {
        byte[] bytes = VerdictCanonicalizer.canonicalBytes("t", "1", "CN=Bank Å, O=Test ,C=SE",
                "00".repeat(64), true, true, "Å", "", "");

        String canonical = new String(bytes, StandardCharsets.UTF_8);
        assertThat(canonical).startsWith("sv1|t|1|CN=Bank Å,O=Test,C=SE|");
        // U+00C5 is two bytes in UTF-8.
        assertThat(canonical).endsWith("|true|true|Å||");
        assertThat(bytes).containsSequence((byte) 0xC3, (byte) 0x85);
    }

    @Test
    void aSerialThatIsNotHexadecimalOrAnIssuerThatIsNotADnIsRefused() {
        assertThatThrownBy(() -> VerdictCanonicalizer.canonicalString("t", "-1f", "CN=x", "", true, true, "", "", ""))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> VerdictCanonicalizer.canonicalString("t", "1f", "not a dn", "", true, true, "", "", ""))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
