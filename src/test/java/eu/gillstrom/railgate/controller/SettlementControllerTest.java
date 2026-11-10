package eu.gillstrom.railgate.controller;

import eu.gillstrom.railgate.audit.RailgateAuditLog;
import eu.gillstrom.railgate.model.SettlementDecision;
import eu.gillstrom.railgate.model.SettlementRequest;
import eu.gillstrom.railgate.service.SettlementOrchestrator;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class SettlementControllerTest {

    private final SettlementOrchestrator orchestrator = mock(SettlementOrchestrator.class);
    private final RailgateAuditLog auditLog = new RailgateAuditLog();
    private final SettlementController controller = new SettlementController(orchestrator, auditLog);

    private ResponseEntity<SettlementDecision> precheck(boolean allow) {
        SettlementDecision decision = SettlementDecision.builder()
                .allow(allow)
                .reasonCode(allow ? "ALLOWED" : "CERT_NOT_FOUND")
                .transactionReference("TX-C")
                .build();
        when(orchestrator.evaluate(any())).thenReturn(decision);
        ResponseEntity<SettlementDecision> response = controller.precheck(new SettlementRequest());
        assertThat(response.getBody()).isSameAs(decision);
        return response;
    }

    @Test
    void anAllowIsAnsweredWith200() {
        assertThat(precheck(true).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void aDenialIsAnsweredWith403() {
        assertThat(precheck(false).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void anEvaluationThatFailsIsRethrownWithTheTransactionReference() {
        IllegalStateException failure = new IllegalStateException("boom");
        when(orchestrator.evaluate(any())).thenThrow(failure);

        assertThatThrownBy(() -> controller.precheck(
                        SettlementRequest.builder().transactionReference("TX-FAILED").build()))
                .isInstanceOfSatisfying(SettlementEvaluationException.class, e -> {
                    assertThat(e.transactionReference()).isEqualTo("TX-FAILED");
                    assertThat(e.getCause()).isSameAs(failure);
                });
    }

    private static final String VALID_REQUEST = "{\"transactionReference\":\"TX-MVC\","
            + "\"debtorIsOrganization\":true,\"creditorIsPrivatePerson\":true}";

    private MockMvc mvc() {
        return MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new SettlementExceptionHandler(auditLog))
                .build();
    }

    /**
     * Until 1.7.0 the settlement was evaluated, recorded and entered in the
     * replay record before the answer was found not to be acceptable, so the
     * rail received 406 for a settlement railgate had allowed.
     */
    @Test
    void aCallerThatDoesNotAcceptJsonIsAnswered406BeforeTheSettlementIsEvaluated() throws Exception {
        mvc().perform(post("/api/v1/settle/precheck")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_XML)
                        .content(VALID_REQUEST))
                .andExpect(status().isNotAcceptable());

        verifyNoInteractions(orchestrator);
        assertThat(auditLog.snapshot()).isEmpty();
    }

    /**
     * Until 1.7.0 the audit trail was read, could not be written as HTML, and
     * the failure was recorded as a denied settlement.
     */
    @Test
    void readingTheAuditTrailWithoutAcceptingJsonIsA406ThatRecordsNothing() throws Exception {
        for (String path : new String[] {"/api/v1/audit", "/api/v1/audit/health"}) {
            mvc().perform(get(path).accept(MediaType.TEXT_HTML)).andExpect(status().isNotAcceptable());
            mvc().perform(get(path).accept(MediaType.APPLICATION_JSON)).andExpect(status().isOk());
        }

        assertThat(auditLog.snapshot()).isEmpty();
    }

    @Test
    void aCallerThatAcceptsJsonOrAnythingIsAnsweredWithTheDecision() throws Exception {
        when(orchestrator.evaluate(any())).thenReturn(SettlementDecision.builder()
                .allow(true).reasonCode("ALLOWED").transactionReference("TX-MVC").build());

        for (MediaType accepted : new MediaType[] {MediaType.APPLICATION_JSON, MediaType.ALL}) {
            mvc().perform(post("/api/v1/settle/precheck")
                            .contentType(MediaType.APPLICATION_JSON)
                            .accept(accepted)
                            .content(VALID_REQUEST))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                    .andExpect(jsonPath("$.reasonCode").value("ALLOWED"));
        }
    }

    @Test
    void aFailedEvaluationOverHttpIsADenyThatNamesTheReference() throws Exception {
        when(orchestrator.evaluate(any())).thenThrow(new IllegalStateException("boom"));

        mvc().perform(post("/api/v1/settle/precheck")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_REQUEST))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.allow").value(false))
                .andExpect(jsonPath("$.reasonCode").value("INTERNAL_ERROR"))
                .andExpect(jsonPath("$.transactionReference").value("TX-MVC"));

        verify(orchestrator).evaluate(any());
        assertThat(auditLog.snapshot()).singleElement()
                .extracting(RailgateAuditLog.AuditEntry::transactionReference).isEqualTo("TX-MVC");
    }

    @Test
    void theAuditEndpointsReturnTheLogAndItsHealth() {
        auditLog.record(SettlementDecision.builder()
                .allow(false)
                .reasonCode("CERT_NOT_FOUND")
                .transactionReference("TX-AUDIT")
                .build());

        assertThat(controller.audit().getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(controller.audit().getBody()).singleElement()
                .extracting(RailgateAuditLog.AuditEntry::transactionReference).isEqualTo("TX-AUDIT");
        assertThat(controller.auditHealth().getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(controller.auditHealth().getBody())
                .isEqualTo(new RailgateAuditLog.AuditLogHealth(1, 10_000, 0));
    }
}
