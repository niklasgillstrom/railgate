package eu.gillstrom.railgate.client;

import eu.gillstrom.railgate.model.PaymentSignature;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FilePaymentNetworkClientTest {

    private static final String DIGEST = "ab".repeat(64);
    private static final String SIGNATURE = "c2lnbmF0dXJl";

    @TempDir
    Path tempDir;

    @Test
    void returnsTheArtefactsRecordedForTheTransactionReference() throws Exception {
        Path file = tempDir.resolve("payment-network.tsv");
        Files.writeString(file, String.join("\n",
                "# reference\tserial\tissuer\tdigest\tsignature",
                "",
                "tx-1\t1a2b\tCN=Issuer One,O=Test,C=SE\t" + DIGEST + "\t" + SIGNATURE,
                "tx-2\t3c4d\tCN=Issuer Two,O=Test,C=SE\t" + DIGEST + "\t" + SIGNATURE), StandardCharsets.UTF_8);

        Optional<PaymentSignature> signature = new FilePaymentNetworkClient(file.toString()).getSignature("tx-2");

        assertThat(signature).isPresent();
        assertThat(signature.get().getCertSerial()).isEqualTo("3c4d");
        assertThat(signature.get().getIssuerDn()).isEqualTo("CN=Issuer Two,O=Test,C=SE");
        assertThat(signature.get().getDigestHex()).isEqualTo(DIGEST);
        assertThat(signature.get().getSignatureBase64()).isEqualTo(SIGNATURE);
    }

    @Test
    void entriesWrittenAfterStartUpAreFound() throws Exception {
        Path file = tempDir.resolve("payment-network.tsv");
        FilePaymentNetworkClient client = new FilePaymentNetworkClient(file.toString());

        assertThat(client.getSignature("tx-late")).isEmpty();

        Files.writeString(file, "tx-late\t1a2b\tCN=Issuer,C=SE\t" + DIGEST + "\t" + SIGNATURE + "\n",
                StandardCharsets.UTF_8);

        assertThat(client.getSignature("tx-late")).isPresent();
    }

    @Test
    void unknownReferenceAndMalformedLinesYieldNothing() throws Exception {
        Path file = tempDir.resolve("payment-network.tsv");
        Files.writeString(file, String.join("\n",
                "tx-short\t1a2b\tCN=Issuer,C=SE\t" + DIGEST,
                "tx-long\t1a2b\tCN=Issuer,C=SE\t" + DIGEST + "\t" + SIGNATURE + "\textra"), StandardCharsets.UTF_8);
        FilePaymentNetworkClient client = new FilePaymentNetworkClient(file.toString());

        assertThat(client.getSignature("tx-unknown")).isEmpty();
        assertThat(client.getSignature("tx-short")).isEmpty();
        assertThat(client.getSignature("tx-long")).isEmpty();
        assertThat(client.getSignature(null)).isEmpty();
    }

    @Test
    void fileModeWithoutAFileIsRefusedAtStartUp() {
        assertThatThrownBy(() -> new FilePaymentNetworkClient(" "))
                .isInstanceOf(IllegalStateException.class);
    }
}
