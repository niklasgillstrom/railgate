package eu.gillstrom.railgate.controller;

import eu.gillstrom.railgate.audit.RailgateAuditLog;
import eu.gillstrom.railgate.model.SettlementDecision;
import eu.gillstrom.railgate.model.SettlementRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * An exception must not become an allow, and must not become a leak.
 */
class SettlementExceptionHandlerTest {

    private RailgateAuditLog auditLog;
    private SettlementExceptionHandler handler;

    @BeforeEach
    void setUp() {
        auditLog = new RailgateAuditLog();
        handler = new SettlementExceptionHandler(auditLog);
    }

    @Test
    void anUnexpectedExceptionBecomesA403Deny() {
        ResponseEntity<SettlementDecision> response =
                handler.handleUnexpected(new IllegalStateException(
                        "jdbc:postgresql://rix-inst-internal:5432/settlements password=hunter2"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        SettlementDecision decision = response.getBody();
        assertThat(decision).isNotNull();
        assertThat(decision.isAllow()).isFalse();
        assertThat(decision.getReasonCode()).isEqualTo("INTERNAL_ERROR");
    }

    @Test
    void theResponseCarriesNothingFromTheException() {
        ResponseEntity<SettlementDecision> response =
                handler.handleUnexpected(new IllegalStateException(
                        "jdbc:postgresql://rix-inst-internal:5432/settlements password=hunter2"));

        SettlementDecision decision = response.getBody();
        assertThat(decision).isNotNull();
        assertThat(decision.getMessage())
                .doesNotContain("jdbc")
                .doesNotContain("hunter2")
                .doesNotContain("IllegalStateException");
    }

    @Test
    void aValidationFailureBecomesA400Deny() throws Exception {
        ResponseEntity<SettlementDecision> response =
                handler.handleInvalidRequest(methodArgumentNotValid());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        SettlementDecision decision = response.getBody();
        assertThat(decision).isNotNull();
        assertThat(decision.isAllow()).isFalse();
        assertThat(decision.getReasonCode()).isEqualTo("INVALID_REQUEST");
    }

    @Test
    void bothOutcomesAreRecordedInTheAuditLog() throws Exception {
        handler.handleUnexpected(new RuntimeException("boom"));
        handler.handleInvalidRequest(methodArgumentNotValid());

        assertThat(auditLog.snapshot())
                .extracting(RailgateAuditLog.AuditEntry::reasonCode)
                .containsExactly("INTERNAL_ERROR", "INVALID_REQUEST");
        assertThat(auditLog.snapshot())
                .allMatch(entry -> !entry.allowed());
    }

    private static MethodArgumentNotValidException methodArgumentNotValid() throws Exception {
        Method precheck = SettlementController.class
                .getMethod("precheck", SettlementRequest.class);
        SettlementRequest request = SettlementRequest.builder()
                .transactionReference("UETR-12345")
                .build();
        return new MethodArgumentNotValidException(
                new MethodParameter(precheck, 0),
                new BeanPropertyBindingResult(request, "settlementRequest"));
    }
}
