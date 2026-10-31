package eu.gillstrom.railgate;

import eu.gillstrom.railgate.client.GatekeeperClient;
import eu.gillstrom.railgate.client.VerdictVerifier;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The {@code dev} profile accepts unsigned gatekeeper verdicts, so that a
 * local run against a gatekeeper without a configured verdict key keeps
 * working. Same configuration as {@link OpenApiExposureDevProfileTest}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@ActiveProfiles("dev")
@TestPropertySource(properties = {
        "railgate.gatekeeper.base-url=https://gatekeeper.test:8443"
})
class DevProfileHardeningDefaultsTest {

    @Autowired
    private ApplicationContext context;

    @Test
    void theDevProfileDoesNotRequireASignedVerdict() {
        VerdictVerifier verifier = (VerdictVerifier) ReflectionTestUtils.getField(
                context.getBean(GatekeeperClient.class), "verdictVerifier");
        assertThat(verifier.isSignatureRequired()).isFalse();
    }
}
