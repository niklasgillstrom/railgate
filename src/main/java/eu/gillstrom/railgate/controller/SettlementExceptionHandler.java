package eu.gillstrom.railgate.controller;

import eu.gillstrom.railgate.audit.RailgateAuditLog;
import eu.gillstrom.railgate.model.SettlementDecision;
import eu.gillstrom.railgate.model.SettlementRequest;
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
 * <p>Three outcomes:
 * <ul>
 *   <li>{@link MethodArgumentNotValidException} — the request did not satisfy
 *       the constraints on {@code SettlementRequest} (a missing party-type
 *       flag, an over-long instrument code). HTTP 400 with
 *       {@code allow=false, reasonCode=INVALID_REQUEST}. The bank can correct
 *       and resubmit.</li>
 *   <li>{@link SettlementEvaluationException} — the request was read and
 *       valid, and its evaluation failed unexpectedly. HTTP 403 with
 *       {@code allow=false, reasonCode=INTERNAL_ERROR}, the same status the
 *       controller uses for an ordinary deny.</li>
 *   <li>Anything else — the request never became a {@code SettlementRequest}
 *       (a body that is not JSON, a content type railgate does not read).
 *       HTTP 403 with {@code INTERNAL_ERROR} as well.</li>
 * </ul>
 *
 * <p>No response carries the exception's message, class name or any
 * field-level validation detail. The caller is an external settlement system;
 * what failed inside railgate is for the operator's log, which does receive
 * the stack trace. The log receives a copy of the exception in which every
 * message is passed through {@link RailgateAuditLog#sanitise}: the message of
 * a parse or conversion failure quotes the request, and written as it stands
 * a line break in it would start a line of the caller's choosing in the
 * operator's log.
 *
 * <p>All three outcomes are written to {@link RailgateAuditLog}. A denied
 * settlement that left no audit record would be indistinguishable, after the
 * fact, from one that was never submitted. The first two carry the transaction
 * reference the request stated (cut to
 * {@value RailgateAuditLog#MAX_FIELD_LENGTH} characters); the third has none,
 * because no request was read. Until 1.7.0 none of them carried one.
 */
@RestControllerAdvice(assignableTypes = SettlementController.class)
@RequiredArgsConstructor
@Slf4j
public class SettlementExceptionHandler {

    /** Bound on each exception message that is written to the log. */
    static final int MAX_LOGGED_MESSAGE_LENGTH = 512;

    /** How many causes of a failure are written to the log. */
    static final int MAX_LOGGED_CAUSES = 8;

    private final RailgateAuditLog auditLog;

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<SettlementDecision> handleInvalidRequest(MethodArgumentNotValidException ex) {
        log.warn("Settlement request rejected by validation with {} error(s); "
                + "no verification was attempted", ex.getBindingResult().getErrorCount());
        return deny(HttpStatus.BAD_REQUEST, "INVALID_REQUEST", statedReference(ex.getBindingResult().getTarget()),
                "Settlement request failed validation. The transaction reference (at most 36 "
                + "characters) and both party-type classification flags are required, and the "
                + "declared certificate serial and the BICs must be within their lengths. No "
                + "verification was attempted and the settlement is not permitted.");
    }

    @ExceptionHandler(SettlementEvaluationException.class)
    public ResponseEntity<SettlementDecision> handleFailedEvaluation(SettlementEvaluationException ex) {
        log.error("Unhandled failure while evaluating a settlement request; "
                + "applying default-deny", sanitised(ex.getCause()));
        return deny(HttpStatus.FORBIDDEN, "INTERNAL_ERROR", ex.transactionReference(),
                "Settlement could not be evaluated. Default-deny applied.");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<SettlementDecision> handleUnexpected(Exception ex) {
        log.error("Unhandled failure before a settlement request could be evaluated; "
                + "applying default-deny", sanitised(ex));
        return deny(HttpStatus.FORBIDDEN, "INTERNAL_ERROR", null,
                "Settlement could not be evaluated. Default-deny applied.");
    }

    private static String statedReference(Object target) {
        return target instanceof SettlementRequest request ? request.getTransactionReference() : null;
    }

    /**
     * A copy of {@code failure} for the log: the same stack traces, and for
     * each of the first {@value #MAX_LOGGED_CAUSES} throwables in the cause
     * chain its {@code toString()} with control characters replaced and cut to
     * {@value #MAX_LOGGED_MESSAGE_LENGTH} characters.
     */
    static Throwable sanitised(Throwable failure) {
        return sanitised(failure, MAX_LOGGED_CAUSES);
    }

    private static Throwable sanitised(Throwable failure, int remaining) {
        if (failure == null || remaining == 0) {
            return null;
        }
        Throwable copy = new LoggedFailure(
                RailgateAuditLog.sanitise(failure.toString(), MAX_LOGGED_MESSAGE_LENGTH),
                sanitised(failure.getCause(), remaining - 1));
        copy.setStackTrace(failure.getStackTrace());
        return copy;
    }

    /** What {@link #sanitised} puts in the log in place of the original exception. */
    static final class LoggedFailure extends RuntimeException {
        LoggedFailure(String description, Throwable cause) {
            super(description, cause, false, true);
        }
    }

    private ResponseEntity<SettlementDecision> deny(HttpStatus status, String reasonCode,
                                                    String transactionReference, String message) {
        SettlementDecision decision = SettlementDecision.builder()
                .allow(false)
                .reasonCode(reasonCode)
                .transactionReference(
                        RailgateAuditLog.sanitise(transactionReference, RailgateAuditLog.MAX_FIELD_LENGTH))
                .message(message)
                .build();
        auditLog.record(decision);
        return ResponseEntity.status(status).body(decision);
    }
}
