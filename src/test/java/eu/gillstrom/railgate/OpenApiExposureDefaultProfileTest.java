package eu.gillstrom.railgate;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The OpenAPI document and Swagger UI are not served unless the {@code dev}
 * profile is active.
 *
 * <p>Both are switched off in every shipped configuration file
 * ({@code springdoc.api-docs.enabled=false},
 * {@code springdoc.swagger-ui.enabled=false}). Neither has a run-time
 * function in this service, and swagger-ui is a third-party JavaScript
 * application whose vulnerabilities would otherwise be part of the deployed
 * surface. This test pins the default; {@link OpenApiExposureDevProfileTest}
 * pins the opt-in.</p>
 *
 * <p>The MockMvc is built without the security filter chain on purpose: the
 * assertion is that the springdoc handlers are absent (404), not that a
 * filter in front of them denies access.</p>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@TestPropertySource(locations = "classpath:tls-test.properties", properties = {
        "railgate.gatekeeper.base-url=https://gatekeeper.test:8443"
})
class OpenApiExposureDefaultProfileTest {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context).build();
    }

    @Test
    void theOpenApiDocumentIsNotServed() throws Exception {
        mvc.perform(get("/v3/api-docs")).andExpect(status().isNotFound());
    }

    @Test
    void swaggerUiIsNotServed() throws Exception {
        mvc.perform(get("/swagger-ui.html")).andExpect(status().isNotFound());
        mvc.perform(get("/swagger-ui/index.html")).andExpect(status().isNotFound());
    }

    /**
     * The swagger-ui package is a WebJar on the class path, and Spring Boot
     * maps {@code /webjars/**} to every WebJar by default, whatever
     * {@code springdoc.swagger-ui.enabled} says. Until 1.7.0 the package was
     * served there in every profile.
     */
    @Test
    void theSwaggerUiPackageIsNotServedAsAWebJarEither() throws Exception {
        Resource[] packaged = new PathMatchingResourcePatternResolver()
                .getResources("classpath*:META-INF/resources/webjars/swagger-ui/*/index.html");
        assertThat(packaged).as("the package is on the class path, so the paths below are real").isNotEmpty();

        for (Resource resource : packaged) {
            String url = resource.getURL().toString();
            String path = url.substring(url.indexOf("/webjars/"));
            mvc.perform(get(path)).andExpect(status().isNotFound());
            mvc.perform(get(path.replace("index.html", "swagger-ui-bundle.js"))).andExpect(status().isNotFound());
        }
        mvc.perform(get("/webjars/swagger-ui/index.html")).andExpect(status().isNotFound());
    }
}
