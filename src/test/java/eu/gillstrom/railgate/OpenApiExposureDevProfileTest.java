package eu.gillstrom.railgate;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * With the {@code dev} profile active, the OpenAPI document and Swagger UI
 * are served. Counterpart of {@link OpenApiExposureDefaultProfileTest}; the
 * two together make the exposure a deliberate choice rather than a default
 * that happens to be in place.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@ActiveProfiles("dev")
@TestPropertySource(properties = {
        "railgate.gatekeeper.base-url=https://gatekeeper.test:8443"
})
class OpenApiExposureDevProfileTest {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context).build();
    }

    @Test
    void theOpenApiDocumentIsServed() throws Exception {
        mvc.perform(get("/v3/api-docs")).andExpect(status().isOk());
    }

    @Test
    void swaggerUiIsServed() throws Exception {
        // springdoc answers /swagger-ui.html with a redirect to the bundled UI.
        mvc.perform(get("/swagger-ui.html")).andExpect(status().is3xxRedirection());
    }
}
