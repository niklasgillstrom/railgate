package eu.gillstrom.railgate.client;

import eu.gillstrom.railgate.model.PaymentSignature;
import eu.gillstrom.railgate.model.VerificationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * Tests for the layer where every fail-open risk in railgate actually lives.
 *
 * <p>The existing orchestrator tests mock {@link GatekeeperClient} entirely, so
 * they exercise only the code that was already correct. These tests drive the
 * real client against a stubbed transport and assert that every abnormal
 * gatekeeper response ends in a deny rather than an allow.</p>
 */
class GatekeeperClientTest {

    private static final String BASE_URL = "http://gatekeeper.test";
    private static final String VERIFY_URL = BASE_URL + "/api/v1/verify";

    private RestTemplate restTemplate;
    private MockRestServiceServer server;
    private GatekeeperClient client;

    @BeforeEach
    void setUp() {
        restTemplate = new RestTemplate();
        server = MockRestServiceServer.bindTo(restTemplate).build();
        client = new GatekeeperClient(restTemplate);
        ReflectionTestUtils.setField(client, "gatekeeperBaseUrl", BASE_URL);
    }

    private static PaymentSignature signature() {
        return PaymentSignature.builder()
                .digestHex("a1b2c3")
                .signatureBase64("c2lnbmF0dXJl")
                .certSerial("0123456789")
                .issuerDn("CN=SEB Customer CA3 v1 for BankID")
                .build();
    }

    @Test
    void forwardsExactlyTheFourDataMinimisedFields() {
        server.expect(requestTo(VERIFY_URL))
                .andExpect(method(HttpMethod.POST))
                .andExpect(jsonPath("$.certSerial").value("0123456789"))
                .andExpect(jsonPath("$.issuerDn").value("CN=SEB Customer CA3 v1 for BankID"))
                .andExpect(jsonPath("$.digestHex").value("a1b2c3"))
                .andExpect(jsonPath("$.signatureBase64").value("c2lnbmF0dXJl"))
                .andExpect(jsonPath("$.length()").value(4))
                .andRespond(withSuccess(
                        "{\"signatureValid\":true,\"compliant\":true,\"auditEntryId\":\"AE-1\"}",
                        MediaType.APPLICATION_JSON));

        VerificationResult result = client.verify(signature());

        server.verify();
        assertThat(result.isSignatureValid()).isTrue();
        assertThat(result.isCompliant()).isTrue();
        assertThat(result.getAuditEntryId()).isEqualTo("AE-1");
    }

    @Test
    void serverErrorYieldsNetworkErrorDeny() {
        server.expect(requestTo(VERIFY_URL)).andRespond(withServerError());

        VerificationResult result = client.verify(signature());

        assertThat(result.isSignatureValid()).isFalse();
        assertThat(result.isCompliant()).isFalse();
        assertThat(result.getReason()).isEqualTo("NETWORK_ERROR");
    }

    @Test
    void emptyBodyYieldsNetworkErrorDeny() {
        server.expect(requestTo(VERIFY_URL))
                .andRespond(withSuccess("", MediaType.APPLICATION_JSON));

        VerificationResult result = client.verify(signature());

        assertThat(result.isSignatureValid()).isFalse();
        assertThat(result.isCompliant()).isFalse();
        assertThat(result.getReason()).isEqualTo("NETWORK_ERROR");
    }

    @Test
    void unparseableBodyYieldsDeny() {
        server.expect(requestTo(VERIFY_URL))
                .andRespond(withSuccess("<html>not json</html>", MediaType.APPLICATION_JSON));

        VerificationResult result = client.verify(signature());

        assertThat(result.isSignatureValid()).isFalse();
        assertThat(result.isCompliant()).isFalse();
    }

    @Test
    void foreignJsonDeserialisesToDenyRatherThanAllow() {
        // A response shaped for some other API must not default to true on any
        // field. Jackson fills the missing booleans with false, which is the
        // fail-closed outcome — this test pins that behaviour.
        server.expect(requestTo(VERIFY_URL))
                .andRespond(withSuccess("{\"status\":\"OK\",\"approved\":true}",
                        MediaType.APPLICATION_JSON));

        VerificationResult result = client.verify(signature());

        assertThat(result.isSignatureValid()).isFalse();
        assertThat(result.isCompliant()).isFalse();
    }

}
