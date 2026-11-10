package eu.gillstrom.railgate.controller;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.core.read.ListAppender;
import eu.gillstrom.railgate.audit.RailgateAuditLog;
import eu.gillstrom.railgate.model.SettlementDecision;
import eu.gillstrom.railgate.model.SettlementRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
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

    // ---------------------------------------------------------------
    // The transaction reference in the record (1.8.0)
    // ---------------------------------------------------------------

    @Test
    void aValidationFailureIsRecordedWithTheReferenceTheRequestStated() throws Exception {
        ResponseEntity<SettlementDecision> response = handler.handleInvalidRequest(methodArgumentNotValid());

        assertThat(response.getBody().getTransactionReference()).isEqualTo("UETR-12345");
        assertThat(auditLog.snapshot()).singleElement()
                .extracting(RailgateAuditLog.AuditEntry::transactionReference).isEqualTo("UETR-12345");
    }

    @Test
    void aStatedReferenceIsCutAndStrippedBeforeItIsAnsweredOrRecorded() throws Exception {
        String stated = "LINE1\r\nLINE2" + "x".repeat(200);
        String expected = ("LINE1  LINE2" + "x".repeat(200)).substring(0, 128);

        ResponseEntity<SettlementDecision> response = handler.handleInvalidRequest(methodArgumentNotValid(
                SettlementRequest.builder().transactionReference(stated).build()));

        assertThat(response.getBody().getTransactionReference()).isEqualTo(expected);
        assertThat(auditLog.snapshot()).singleElement()
                .extracting(RailgateAuditLog.AuditEntry::transactionReference).isEqualTo(expected);
    }

    @Test
    void aValidationFailureOfSomethingElseThanASettlementRequestHasNoReference() throws Exception {
        ResponseEntity<SettlementDecision> response = handler.handleInvalidRequest(
                methodArgumentNotValid("not a settlement request"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody().getTransactionReference()).isNull();
    }

    @Test
    void aFailedEvaluationIsA403DenyRecordedWithItsReference() {
        ResponseEntity<SettlementDecision> response = handler.handleFailedEvaluation(
                new SettlementEvaluationException("UETR-777", new IllegalStateException("journal on fire")));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        SettlementDecision decision = response.getBody();
        assertThat(decision.isAllow()).isFalse();
        assertThat(decision.getReasonCode()).isEqualTo("INTERNAL_ERROR");
        assertThat(decision.getTransactionReference()).isEqualTo("UETR-777");
        assertThat(decision.getMessage()).doesNotContain("journal", "IllegalStateException");
        assertThat(auditLog.snapshot()).singleElement().satisfies(entry -> {
            assertThat(entry.allowed()).isFalse();
            assertThat(entry.reasonCode()).isEqualTo("INTERNAL_ERROR");
            assertThat(entry.transactionReference()).isEqualTo("UETR-777");
        });
    }

    @Test
    void aRequestThatWasNeverReadIsRecordedWithoutAReference() {
        handler.handleUnexpected(new IllegalArgumentException("not JSON"));

        assertThat(auditLog.snapshot()).singleElement()
                .extracting(RailgateAuditLog.AuditEntry::transactionReference).isNull();
    }

    // ---------------------------------------------------------------
    // What reaches the operator's log (1.8.0)
    // ---------------------------------------------------------------

    /**
     * The message of a parse failure quotes the request. Until 1.7.0 the
     * exception was logged as it was, so a line break in the request body
     * started a line of the caller's choosing in the operator's log.
     */
    @Test
    void anExceptionMessageCannotStartALineInTheLog() {
        Logger logger = (Logger) LoggerFactory.getLogger(SettlementExceptionHandler.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            String forged = "Unexpected token\r\n2026-11-10 WARN Settlement ALLOWED: ref=FORGED\u2028x";
            handler.handleUnexpected(new IllegalStateException("outer\nline", new RuntimeException(forged)));
            handler.handleFailedEvaluation(
                    new SettlementEvaluationException("UETR-1", new IllegalStateException(forged)));

            assertThat(appender.list).hasSize(2).allSatisfy(event -> {
                assertThat(event.getLevel()).isEqualTo(Level.ERROR);
                assertThat(event.getFormattedMessage()).doesNotContain("\r", "\n");
                for (IThrowableProxy logged = event.getThrowableProxy(); logged != null; logged = logged.getCause()) {
                    assertThat(logged.getMessage()).doesNotContain("\r", "\n", "\u2028");
                    assertThat(logged.getStackTraceElementProxyArray()).isNotEmpty();
                }
            });
            assertThat(appender.list.get(0).getThrowableProxy().getMessage())
                    .isEqualTo("java.lang.IllegalStateException: outer line");
            assertThat(appender.list.get(0).getThrowableProxy().getCause().getMessage())
                    .isEqualTo("java.lang.RuntimeException: Unexpected token  2026-11-10 WARN Settlement ALLOWED: "
                            + "ref=FORGED x");
            assertThat(appender.list.get(1).getThrowableProxy().getMessage())
                    .as("the cause of the evaluation failure, not its wrapper")
                    .startsWith("java.lang.IllegalStateException: Unexpected token");
        } finally {
            logger.detachAppender(appender);
        }
    }

    @Test
    void theLoggedCopyKeepsEachStackTraceAndBoundsMessagesAndCauses() {
        Throwable chain = null;
        for (int i = SettlementExceptionHandler.MAX_LOGGED_CAUSES + 2; i >= 1; i--) {
            chain = new IllegalStateException("cause " + i, chain);
        }
        Throwable longMessage = new RuntimeException("m".repeat(2000), chain);

        Throwable copy = SettlementExceptionHandler.sanitised(longMessage);

        assertThat(copy).isInstanceOf(SettlementExceptionHandler.LoggedFailure.class);
        assertThat(copy.getMessage()).hasSize(SettlementExceptionHandler.MAX_LOGGED_MESSAGE_LENGTH)
                .startsWith("java.lang.RuntimeException: mmm");
        assertThat(copy.getStackTrace()).isEqualTo(longMessage.getStackTrace());
        assertThat(copy.getCause().getMessage()).isEqualTo("java.lang.IllegalStateException: cause 1");
        assertThat(copy.getCause().getStackTrace()).isEqualTo(chain.getStackTrace());

        int depth = 0;
        for (Throwable t = copy; t != null; t = t.getCause()) {
            depth++;
        }
        assertThat(depth).as("the outermost throwable and its first causes").isEqualTo(
                SettlementExceptionHandler.MAX_LOGGED_CAUSES);
        assertThat(SettlementExceptionHandler.sanitised(null)).isNull();
    }

    private static MethodArgumentNotValidException methodArgumentNotValid() throws Exception {
        return methodArgumentNotValid(SettlementRequest.builder()
                .transactionReference("UETR-12345")
                .build());
    }

    private static MethodArgumentNotValidException methodArgumentNotValid(Object target) throws Exception {
        Method precheck = SettlementController.class
                .getMethod("precheck", SettlementRequest.class);
        return new MethodArgumentNotValidException(
                new MethodParameter(precheck, 0),
                new BeanPropertyBindingResult(target, "settlementRequest"));
    }
}
