package eu.gillstrom.railgate;

import eu.gillstrom.railgate.client.GatekeeperClient;
import eu.gillstrom.railgate.controller.SettlementExceptionHandler;
import eu.gillstrom.railgate.service.SettlementOrchestrator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The application starts.
 *
 * <p>This test exists because 1.3.0 could not. {@code GatekeeperClient} was
 * given a second, package-private constructor as a test seam, which left the
 * class with two constructors and no {@code @Autowired} on either; Spring
 * cannot choose between them and has no no-arg constructor to fall back on,
 * so context refresh failed and the service would not boot. The whole suite
 * stayed green, because every test either constructed its collaborators
 * directly or used the test seam. Nothing read {@code application.yml} and
 * nothing built the bean graph.</p>
 *
 * <p>The consequence was that the timeout fix released in 1.3.0 — the reason
 * that constructor was touched — never ran anywhere but in a unit test.</p>
 *
 * <p>The base URL is overridden with an {@code https} value rather than by
 * setting {@code railgate.gatekeeper.allow-insecure-http=true}: the override
 * would switch off the scheme check this release adds, so the test would
 * stop noticing if the shipped default regressed to {@code http}. Nothing is
 * listening on the URL and nothing needs to be — the client is constructed,
 * not called.</p>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@TestPropertySource(properties = "railgate.gatekeeper.base-url=https://gatekeeper.test:8443")
class ApplicationContextLoadsTest {

    @Autowired
    private ApplicationContext context;

    @Test
    void theContextLoadsFromTheShippedConfiguration() {
        assertThat(context).isNotNull();
        assertThat(context.getBean(GatekeeperClient.class))
                .as("the bean whose two-constructor ambiguity blocked start-up in 1.3.0")
                .isNotNull();
        assertThat(context.getBean(SettlementOrchestrator.class)).isNotNull();
        assertThat(context.getBean(SettlementExceptionHandler.class)).isNotNull();
    }

    @Test
    void theSecurityFilterChainsAreBuilt() {
        assertThat(context.getBeansOfType(SecurityFilterChain.class))
                .as("one chain for the stateless /api/v1/** API, one for everything else")
                .hasSize(2);
    }
}
