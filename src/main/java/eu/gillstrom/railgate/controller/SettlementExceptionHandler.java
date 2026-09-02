package eu.gillstrom.railgate.controller;

import eu.gillstrom.railgate.audit.RailgateAuditLog;
import eu.gillstrom.railgate.model.SettlementDecision;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Turns any unhandled failure of the settlement endpoints into a deny.
 *
 * <p>Without this advice, an exception escaping
 * {@link SettlementController#precheck} reached Spring's default error
 * handling and produced HTTP 500 with an error body that is not a
 * {@link SettlementDecision}. A settlement pipeline that treats a
 * non-{@code allow=false} answer as anything other than a block — or that
 * fails to parse the body and falls back to its own default — would settle a
 * payment railgate never verified. Default-deny has to hold for the failure
 * modes too, not only for the ones the orchestrator anticipated.
 *
 * <p>Two outcomes:
 * <ul>
 *   <li>{@link MethodArgumentNotValidException} — the request did not satisfy
 *       the constraints on {@code SettlementRequest} (a missing party-type
 *       flag, an over-long instrument code). HTTP 400 with
 *       {@code allow=false, reasonCode=INVALID_REQUEST}. The bank can correct
 *       and resubmit.</li>
 *   <li>Anything else — HTTP 403 with
 *       {@code allow=false, reasonCode=INTERNAL_ERROR}, the same status the
 *       controller uses for an ordinary deny.</li>
 * </ul>
 *
 * <p>Neither response carries the exception's message, class name or any
 * field-level validation detail. The caller is an external settlement system;
 * what failed inside railgate is for the operator's log, which does receive
 * the stack trace.
 *
 * <p>Both outcomes are written to {@link RailgateAuditLog}. A denied
 * settlement that left no audit record would be indistinguishable, after the
 * fact, from one that was never submitted.
 */
@RestControllerAdvice(assignableTypes = SettlementController.class)
@RequiredArgsConstructor
@Slf4j
public class SettlementExceptionHandler {

    private final RailgateAuditLog auditLog;

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<SettlementDecision> handleInvalidRequest(MethodArgumentNotValidException ex) {
        log.warn("Settlement request rejected by validation with {} error(s); "
                + "no verification was attempted", ex.getBindingResult().getErrorCount());
        return deny(HttpStatus.BAD_REQUEST, "INVALID_REQUEST",
                "Settlement request failed validation. The transaction reference and both "
                + "party-type classification flags are required. No verification was "
                + "attempted and the settlement is not permitted.");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<SettlementDecision> handleUnexpected(Exception ex) {
        log.error("Unhandled failure while evaluating a settlement request; "
                + "applying default-deny", ex);
        return deny(HttpStatus.FORBIDDEN, "INTERNAL_ERROR",
                "Settlement could not be evaluated. Default-deny applied.");
    }

    private ResponseEntity<SettlementDecision> deny(HttpStatus status, String reasonCode, String message) {
        SettlementDecision decision = SettlementDecision.builder()
                .allow(false)
                .reasonCode(reasonCode)
                .message(message)
                .build();
        auditLog.record(decision);
        return ResponseEntity.status(status).body(decision);
    }
}
