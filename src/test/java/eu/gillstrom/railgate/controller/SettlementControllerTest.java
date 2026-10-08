package eu.gillstrom.railgate.controller;

import eu.gillstrom.railgate.audit.RailgateAuditLog;
import eu.gillstrom.railgate.model.SettlementDecision;
import eu.gillstrom.railgate.model.SettlementRequest;
import eu.gillstrom.railgate.service.SettlementOrchestrator;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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
