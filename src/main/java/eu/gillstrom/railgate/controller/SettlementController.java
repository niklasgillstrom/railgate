package eu.gillstrom.railgate.controller;

import eu.gillstrom.railgate.audit.RailgateAuditLog;
import eu.gillstrom.railgate.model.SettlementDecision;
import eu.gillstrom.railgate.model.SettlementRequest;
import eu.gillstrom.railgate.service.SettlementOrchestrator;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Settlement-rail enforcement HTTP endpoint.
 *
 * <p>Production deployments at a central-bank settlement rail would invoke
 * {@code POST /api/v1/settle/precheck} synchronously as part of the
 * pacs.008 processing pipeline before forwarding the message for
 * settlement. {@code allow = true} permits the message to continue;
 * {@code allow = false} blocks the settlement and returns the structured
 * reason code to the originating bank.
 *
 * <p>{@code GET /api/v1/audit} returns the retained audit trail (at most the
 * newest 10 000 entries, {@code RailgateAuditLog.MAX_ENTRIES}) for inspection by supervisory
 * staff.
 *
 * <p>Every endpoint answers in JSON and is mapped for callers that accept
 * JSON only: a request whose {@code Accept} header excludes it is answered 406
 * without reaching a method of this class. Until 1.7.0 such a request was
 * handled first. Its answer then could not be written, which
 * {@link SettlementExceptionHandler} recorded as a denied settlement with
 * {@code INTERNAL_ERROR}, also when the request was a {@code GET} of the
 * audit trail.
 */
@RestController
@RequestMapping(value = "/api/v1", produces = MediaType.APPLICATION_JSON_VALUE)
@RequiredArgsConstructor
public class SettlementController {

    private final SettlementOrchestrator orchestrator;
    private final RailgateAuditLog auditLog;

    /**
     * Pre-settlement compliance check.
     *
     * <p>A request whose {@code Accept} header excludes
     * {@code application/json} is answered 406 before the settlement is
     * evaluated (see the class comment). Until 1.7.0 it was evaluated,
     * recorded and, when allowed, entered in the replay record, and only then
     * answered 406, so the rail was told nothing about a settlement railgate
     * had allowed.</p>
     *
     * @param request abstracted settlement request derived from the
     *     incoming pacs.008 (or equivalent)
     * @return decision: allow or default-deny with reason code
     * @throws SettlementEvaluationException when the evaluation fails
     *     unexpectedly; {@link SettlementExceptionHandler} answers it with a
     *     deny that names the transaction reference
     */
    @PostMapping("/settle/precheck")
    public ResponseEntity<SettlementDecision> precheck(@RequestBody @Valid SettlementRequest request) {
        SettlementDecision decision;
        try {
            decision = orchestrator.evaluate(request);
        } catch (RuntimeException e) {
            throw new SettlementEvaluationException(request.getTransactionReference(), e);
        }
        if (decision.isAllow()) {
            return ResponseEntity.ok(decision);
        }
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(decision);
    }

    /**
     * Audit trail of railgate decisions, for supervisory inspection.
     *
     * @return the retained decisions in chronological order; older ones are
     *         evicted once the log is full (see {@link #auditHealth()})
     */
    @GetMapping("/audit")
    public ResponseEntity<List<RailgateAuditLog.AuditEntry>> audit() {
        return ResponseEntity.ok(auditLog.snapshot());
    }

    /**
     * Operational state of the bounded audit log.
     *
     * <p>Reports how many entries are retained, the retention cap, and how
     * many have been discarded at that cap since start-up. A non-zero
     * {@code evictedCount} means the supervisory record read from
     * {@code GET /api/v1/audit} is incomplete, which is not otherwise visible
     * from the snapshot itself.
     *
     * @return retained, capped and discarded counts
     */
    @GetMapping("/audit/health")
    public ResponseEntity<RailgateAuditLog.AuditLogHealth> auditHealth() {
        return ResponseEntity.ok(auditLog.health());
    }
}
