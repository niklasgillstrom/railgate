package eu.gillstrom.railgate;

import eu.gillstrom.railgate.client.GatekeeperClient;
import eu.gillstrom.railgate.client.HttpPaymentNetworkClient;
import eu.gillstrom.railgate.client.PaymentNetworkClient;
import eu.gillstrom.railgate.client.VerdictVerifier;
import eu.gillstrom.railgate.replay.ReplayGuard;
import eu.gillstrom.railgate.service.SettlementOrchestrator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The application starts with the hardened configuration: the HTTP
 * payment-network client with a pinned operator certificate, a pinned
 * gatekeeper verdict key, and a replay journal on disk. Nothing is listening
 * on either URL; the clients are constructed, not called.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@TestPropertySource(locations = "classpath:tls-test.properties", properties = {
        "railgate.gatekeeper.base-url=https://gatekeeper.test:8443",
        "railgate.gatekeeper.trusted-keys=classpath:signing/gatekeeper-cert.pem",
        "railgate.payment-network.mode=http",
        "railgate.payment-network.base-url=https://payment-network-operator.test",
        "railgate.payment-network.trusted-keys=classpath:signing/operator-cert.pem"
})
class HttpModeContextLoadsTest {

    @DynamicPropertySource
    static void replayJournal(DynamicPropertyRegistry registry) throws IOException {
        Path directory = Files.createTempDirectory("railgate-replay");
        directory.toFile().deleteOnExit();
        registry.add("railgate.replay.path", () -> directory.resolve("replay.journal").toString());
    }

    @Autowired
    private ApplicationContext context;

    @Test
    void theHardenedConfigurationLoads() {
        assertThat(context.getBean(PaymentNetworkClient.class)).isInstanceOf(HttpPaymentNetworkClient.class);
        assertThat(context.getBean(ReplayGuard.class).isJournalled()).isTrue();
        assertThat(context.getBean(SettlementOrchestrator.class)).isNotNull();
        VerdictVerifier verifier = (VerdictVerifier) ReflectionTestUtils.getField(
                context.getBean(GatekeeperClient.class), "verdictVerifier");
        assertThat(verifier.isSignatureRequired()).isTrue();
    }
}
