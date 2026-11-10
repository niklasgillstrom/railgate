package eu.gillstrom.railgate.security;

import jakarta.servlet.Filter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * No request leaves a server session behind, with or without credentials,
 * inside or outside {@code /api/v1/**}.
 *
 * <p>Until 1.7.0 only the {@code /api/v1/**} chain was stateless. The chain
 * for every other path used form login, so a request without credentials to
 * any other path — an unknown one included — was answered with a redirect to
 * a login page or a 401 and a new session that lived for the session timeout.
 * Measured against 1.7.0: 3,000 such requests left 3,000 sessions of about
 * 9 kB each. A caller needs no credentials for that.</p>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@TestPropertySource(locations = "classpath:tls-test.properties", properties = {
        "railgate.gatekeeper.base-url=https://gatekeeper.test:8443",
        "spring.security.user.name=rail",
        "spring.security.user.password=test-only"
})
class SecurityConfigStatelessTest {

    private static final String BASIC = "Basic "
            + Base64.getEncoder().encodeToString("rail:test-only".getBytes(StandardCharsets.UTF_8));

    @Autowired
    private WebApplicationContext context;

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context)
                .addFilters(context.getBean("springSecurityFilterChain", Filter.class))
                .build();
    }

    private MvcResult perform(MockHttpServletRequestBuilder request) throws Exception {
        // What a browser sends: with form login this was the request that got
        // the redirect to the login page.
        return mvc.perform(request.header(HttpHeaders.ACCEPT, "text/html")).andReturn();
    }

    private static void assertNothingLeftBehind(MvcResult result) {
        assertThat(result.getRequest().getSession(false)).as("server session").isNull();
        assertThat(result.getResponse().getHeader(HttpHeaders.SET_COOKIE)).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/", "/x", "/login", "/logout", "/swagger-ui.html", "/v3/api-docs", "/error",
        "/api/v1/audit", "/api/v1/settle/precheck"})
    void aRequestWithoutCredentialsIsAnswered401AndCreatesNoSession(String path) throws Exception {
        for (MockHttpServletRequestBuilder request : new MockHttpServletRequestBuilder[] {
                get(path), post(path).contentType("application/json").content("{}")}) {
            MvcResult result = perform(request);

            assertThat(result.getResponse().getStatus()).as(path).isEqualTo(401);
            assertThat(result.getResponse().getHeader(HttpHeaders.WWW_AUTHENTICATE)).startsWith("Basic");
            assertThat(result.getResponse().getHeader(HttpHeaders.LOCATION)).as("no login-page redirect").isNull();
            assertNothingLeftBehind(result);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"/x", "/login", "/api/v1/audit/health"})
    void aRequestWithCredentialsCreatesNoSessionEither(String path) throws Exception {
        for (MockHttpServletRequestBuilder request : new MockHttpServletRequestBuilder[] {
                get(path), post(path).contentType("application/json").content("{}")}) {
            MvcResult result = perform(request.header(HttpHeaders.AUTHORIZATION, BASIC));

            assertThat(result.getResponse().getStatus()).as(path).isNotIn(401, 403);
            assertNothingLeftBehind(result);
        }
    }
}
