package eu.gillstrom.railgate.client;

import eu.gillstrom.railgate.model.PaymentSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/**
 * File-backed {@link PaymentNetworkClient} for local end-to-end runs of the
 * reference implementation. Selected with
 * {@code railgate.payment-network.mode=file}; the file is named by
 * {@code railgate.payment-network.file}.
 *
 * <p>Each line holds one transaction as five tab-separated fields:
 * {@code transactionReference}, {@code certSerial}, {@code issuerDn},
 * {@code digestHex} and {@code signatureBase64}. Blank lines and lines
 * starting with {@code #} are ignored. The file is read on every lookup, so
 * entries added while railgate is running are visible immediately. A missing
 * or unreadable file, or a malformed line, yields no artefacts, which the
 * orchestrator answers with {@code DORA_32_AUDIT_MISSING}.
 *
 * <p>NOT for production: the payment-network operator is the only legitimate
 * source of signature artefacts.
 */
@Component
@ConditionalOnProperty(prefix = "railgate.payment-network", name = "mode", havingValue = "file")
public class FilePaymentNetworkClient implements PaymentNetworkClient {

    private static final Logger log = LoggerFactory.getLogger(FilePaymentNetworkClient.class);

    private final Path file;

    public FilePaymentNetworkClient(@Value("${railgate.payment-network.file:}") String file) {
        if (file == null || file.isBlank()) {
            throw new IllegalStateException(
                    "railgate.payment-network.mode=file requires railgate.payment-network.file");
        }
        this.file = Path.of(file.trim());
        log.warn("FilePaymentNetworkClient is active: signature artefacts are read from {}. "
                + "NOT for production.", this.file);
    }

    @Override
    public Optional<PaymentSignature> getSignature(String transactionReference) {
        if (transactionReference == null || transactionReference.isBlank()) {
            return Optional.empty();
        }
        List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            log.warn("Payment-network file {} could not be read: {}", file, e.getClass().getSimpleName());
            return Optional.empty();
        }
        for (String line : lines) {
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }
            String[] fields = line.split("\t", -1);
            if (fields.length != 5 || !fields[0].equals(transactionReference)) {
                continue;
            }
            return Optional.of(PaymentSignature.builder()
                    .certSerial(fields[1].trim())
                    .issuerDn(fields[2].trim())
                    .digestHex(fields[3].trim())
                    .signatureBase64(fields[4].trim())
                    .build());
        }
        return Optional.empty();
    }
}
