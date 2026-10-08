package eu.gillstrom.railgate.security;

import eu.gillstrom.railgate.RailgateApplication;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.URI;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The shipped configuration, started for real on a random port. */
class ListenerTlsStartUpTest {

    private static SpringApplicationBuilder app(String... properties) {
        return new SpringApplicationBuilder(RailgateApplication.class)
                .web(WebApplicationType.SERVLET)
                .properties("server.port=0", "railgate.gatekeeper.base-url=https://gatekeeper.test:8443")
                .properties(properties);
    }

    @Test
    void theShippedConfigurationDoesNotStartWithoutTls() {
        assertThatThrownBy(() -> app().run().close())
                .rootCause()
                .isInstanceOf(IllegalStateException.class)
                .hasMessageStartingWith("railgate's listener has no TLS");
    }

    @Test
    void withACertificateTheListenerSpeaksTls() throws Exception {
        try (ConfigurableApplicationContext context = app(
                "server.ssl.bundle=railgate-test",
                "spring.ssl.bundle.pem.railgate-test.keystore.certificate=classpath:tls/test-cert.pem",
                "spring.ssl.bundle.pem.railgate-test.keystore.private-key=classpath:tls/test-key.pem",
                "spring.security.user.name=rail", "spring.security.user.password=test-only").run()) {
            int port = ((WebServerApplicationContext) context).getWebServer().getPort();
            SSLContext ssl = SSLContext.getInstance("TLS");
            ssl.init(null, new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] c, String a) { }
                public void checkServerTrusted(X509Certificate[] c, String a) { }
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }}, null);
            HttpsURLConnection connection = (HttpsURLConnection) URI.create(
                    "https://localhost:" + port + "/api/v1/audit/health").toURL().openConnection(java.net.Proxy.NO_PROXY);
            connection.setSSLSocketFactory(ssl.getSocketFactory());
            connection.setHostnameVerifier((h, s) -> true);
            assertThat(connection.getResponseCode()).as("TLS handshake done, Basic auth required").isEqualTo(401);
            assertThat(connection.getCipherSuite()).isNotBlank();

            // Outside /api/v1 the default chain still requires a login.
            HttpsURLConnection outside = (HttpsURLConnection) URI.create(
                    "https://localhost:" + port + "/").toURL().openConnection(java.net.Proxy.NO_PROXY);
            outside.setSSLSocketFactory(ssl.getSocketFactory());
            outside.setHostnameVerifier((h, s) -> true);
            outside.setInstanceFollowRedirects(false);
            assertThat(outside.getResponseCode()).isEqualTo(401);

            // An authenticated request whose body exceeds the 16 KB default.
            HttpsURLConnection post = (HttpsURLConnection) URI.create(
                    "https://localhost:" + port + "/api/v1/settle/precheck").toURL().openConnection(java.net.Proxy.NO_PROXY);
            post.setSSLSocketFactory(ssl.getSocketFactory());
            post.setHostnameVerifier((h, s) -> true);
            post.setRequestMethod("POST");
            post.setDoOutput(true);
            post.setRequestProperty("Content-Type", "application/json");
            post.setRequestProperty("Authorization", "Basic " + java.util.Base64.getEncoder()
                    .encodeToString("rail:test-only".getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
            byte[] body = ("{\"transactionReference\":\"" + "x".repeat(17 * 1024) + "\"}")
                    .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            post.setFixedLengthStreamingMode(body.length);
            post.getOutputStream().write(body);
            assertThat(post.getResponseCode()).isEqualTo(413);
        }
    }
}
