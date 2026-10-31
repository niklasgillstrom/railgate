package eu.gillstrom.railgate;

import eu.gillstrom.railgate.client.GatekeeperClient;
import eu.gillstrom.railgate.client.InMemoryPaymentNetworkClient;
import eu.gillstrom.railgate.client.PaymentNetworkClient;
import eu.gillstrom.railgate.client.VerdictVerifier;
import eu.gillstrom.railgate.replay.ReplayGuard;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Outside the {@code dev} profile a signed gatekeeper verdict is required by
 * default, and without {@code railgate.replay.path} the replay record is held
 * in memory. Same configuration as {@link ApplicationContextLoadsTest}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@TestPropertySource(locations = "classpath:tls-test.properties", properties = "railgate.gatekeeper.base-url=https://gatekeeper.test:8443")
class DefaultProfileHardeningDefaultsTest {

    @Autowired
    private ApplicationContext context;

    @Test
    void aSignedVerdictIsRequiredAndTheReplayRecordIsInMemory() {
        VerdictVerifier verifier = (VerdictVerifier) ReflectionTestUtils.getField(
                context.getBean(GatekeeperClient.class), "verdictVerifier");
        assertThat(verifier.isSignatureRequired()).isTrue();
        assertThat(context.getBean(ReplayGuard.class).isJournalled()).isFalse();
        assertThat(context.getBean(PaymentNetworkClient.class)).isInstanceOf(InMemoryPaymentNetworkClient.class);
    }
}
