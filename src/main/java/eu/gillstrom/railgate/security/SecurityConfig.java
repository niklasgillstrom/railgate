package eu.gillstrom.railgate.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security configuration for the railgate API.
 *
 * <h2>Why an explicit chain is needed</h2>
 *
 * <p>{@code spring-boot-starter-security} is on the classpath, so its default
 * chain applied to every path: session-based, CSRF-protected, form-login. For
 * a stateless JSON API called machine-to-machine by a settlement system that
 * is the wrong shape twice over. CSRF tokens are meaningless without a
 * browser session and without cookies to ride on, and a settlement pipeline
 * cannot follow a login-page redirect. The practical result was that
 * {@code POST /api/v1/settle/precheck} was answered with 401 or 403 by the
 * CSRF filter, before the orchestrator ever ran.
 *
 * <h2>What this configures</h2>
 *
 * <ul>
 *   <li><b>{@code /api/v1/**}</b> — CSRF disabled, sessions stateless,
 *       every request authenticated. HTTP Basic is wired as the reference
 *       mechanism so the chain is usable out of the box.</li>
 *   <li><b>Everything else</b> (Swagger UI, OpenAPI document, error paths) —
 *       the Spring Boot default posture: authenticated, with form login and
 *       HTTP Basic, CSRF on. Declaring any {@code SecurityFilterChain} bean
 *       switches off Boot's auto-configured chain, so the default is
 *       reproduced here rather than inherited.</li>
 * </ul>
 *
 * <h2>What the deployer must decide</h2>
 *
 * <p>The authentication mechanism is not fixed here. A production deployment
 * at a central-bank rail authenticates the settlement system with mTLS,
 * which is a Tomcat/reverse-proxy concern (a truststore via
 * {@code server.ssl.trust-store-*} and {@code server.ssl.client-auth=need})
 * plus an {@code .x509(...)} clause on the {@code /api/v1/**} chain in place
 * of {@code httpBasic}. gatekeeper's {@code SecurityConfig} shows that
 * arrangement with principal extraction and role mapping. railgate ships the
 * Basic variant because it has no role model of its own: every caller of
 * {@code /api/v1/**} is the settlement rail. See {@code README.md}.
 */
@Configuration
public class SecurityConfig {

    /**
     * Stateless JSON API. Ordered ahead of the default chain so that its
     * {@code securityMatcher} wins for {@code /api/v1/**}.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/v1/**")
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session ->
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    /** Everything outside the API keeps Spring Boot's default posture. */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .formLogin(Customizer.withDefaults())
            .httpBasic(Customizer.withDefaults());
        return http.build();
    }
}
