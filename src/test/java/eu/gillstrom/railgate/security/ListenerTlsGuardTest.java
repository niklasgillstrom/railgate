package eu.gillstrom.railgate.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * railgate's own listener must be TLS: {@code /api/v1/**} is authenticated
 * with HTTP Basic, whose credentials, like the settlement verdicts, travel
 * in clear over plain HTTP.
 */
class ListenerTlsGuardTest {

    private static void start(MockEnvironment env, boolean allowInsecure) {
        new ListenerTlsGuard(env, allowInsecure);
    }

    @Test
    void aListenerWithoutTlsIsAStartUpFailure() {
        assertThatThrownBy(() -> start(new MockEnvironment(), false))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("server.ssl");
    }

    @Test
    void sslSwitchedOffIsAStartUpFailure() {
        MockEnvironment env = new MockEnvironment()
                .withProperty("server.ssl.bundle", "rail")
                .withProperty("server.ssl.enabled", "false");
        assertThatThrownBy(() -> start(env, false)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void sslEnabledWithoutKeyMaterialIsAStartUpFailure() {
        MockEnvironment env = new MockEnvironment().withProperty("server.ssl.enabled", "true");
        assertThatThrownBy(() -> start(env, false)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void aBundleKeyStoreOrCertificateIsTls() {
        for (String property : new String[]{"server.ssl.bundle", "server.ssl.key-store", "server.ssl.certificate"}) {
            MockEnvironment env = new MockEnvironment().withProperty(property, "x");
            assertThatCode(() -> start(env, false)).as(property).doesNotThrowAnyException();
        }
    }

    @Test
    void aBlankBundleIsNoKeyMaterial() {
        MockEnvironment env = new MockEnvironment().withProperty("server.ssl.bundle", " ");
        assertThatThrownBy(() -> start(env, false)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void theDevelopmentOverrideAllowsPlainHttp() {
        assertThatCode(() -> start(new MockEnvironment(), true)).doesNotThrowAnyException();
    }
}
