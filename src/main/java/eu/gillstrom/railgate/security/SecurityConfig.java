package eu.gillstrom.railgate.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security configuration for railgate.
 *
 * <h2>Why an explicit chain is needed</h2>
 *
 * <p>{@code spring-boot-starter-security} is on the classpath, so without a
 * chain of its own the application gets Spring Boot's default on every path:
 * session-based, CSRF-protected, form-login. For a stateless JSON API called
 * machine-to-machine by a settlement system that is the wrong shape twice
 * over. CSRF tokens are meaningless without a browser session and without
 * cookies to ride on, and a settlement pipeline cannot follow a login-page
 * redirect. The practical result, before 1.4.0, was that
 * {@code POST /api/v1/settle/precheck} was answered with 401 or 403 by the
 * CSRF filter, before the orchestrator ever ran.
 *
 * <h2>What this configures</h2>
 *
 * <p>One chain for every path — {@code /api/v1/**}, Swagger UI and the
 * OpenAPI document under the {@code dev} profile, error paths, unknown
 * paths: every request authenticated, HTTP Basic as the reference mechanism
 * so the chain is usable out of the box, sessions stateless, no form login,
 * no logout endpoint, no CSRF token. A request without credentials is
 * answered 401 and leaves nothing behind on the server.
 *
 * <p>From 1.4.0 to 1.7.0 there were two chains: this one, limited to
 * {@code /api/v1/**}, and a second one for every other path that reproduced
 * the Spring Boot default (form login, sessions, CSRF on). Every
 * unauthenticated request to a path outside {@code /api/v1/**} then left a
 * server session behind for the session timeout (30 minutes), so a caller
 * without credentials could exhaust the heap. There is no state-changing
 * endpoint outside {@code /api/v1/**} for a CSRF token to protect, and with
 * CSRF protection on, an unauthenticated {@code POST} creates a session to
 * hold the token even under {@link SessionCreationPolicy#STATELESS}. Once the
 * second chain was made stateless it no longer differed from the first in
 * anything a request could observe, so 1.8.0 has one.
 *
 * <h2>What the deployer must decide</h2>
 *
 * <p>The authentication mechanism is not fixed here. A production deployment
 * at a central-bank rail authenticates the settlement system with mTLS,
 * which is a Tomcat/reverse-proxy concern (a truststore via
 * {@code server.ssl.trust-store-*} and {@code server.ssl.client-auth=need})
 * plus an {@code .x509(...)} clause on the chain in place of
 * {@code httpBasic}. gatekeeper's {@code SecurityConfig} shows that
 * arrangement with principal extraction and role mapping. railgate ships the
 * Basic variant because it has no role model of its own: every caller is the
 * settlement rail. See {@code README.md}.
 */
@Configuration
public class SecurityConfig {

    /**
     * The one chain, for every path: authenticated and stateless.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .logout(logout -> logout.disable())
            .sessionManagement(session ->
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .httpBasic(Customizer.withDefaults());
        return http.build();
    }
}
