package eu.gillstrom.railgate.controller;

import eu.gillstrom.railgate.audit.RailgateAuditLog;
import eu.gillstrom.railgate.model.SettlementDecision;
import eu.gillstrom.railgate.model.SettlementRequest;
import eu.gillstrom.railgate.service.SettlementOrchestrator;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
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
 * <p>{@code GET /api/v1/audit} returns the full audit trail for inspection
 * by supervisory staff.
 */
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class SettlementController {

    private final SettlementOrchestrator orchestrator;
    private final RailgateAuditLog auditLog;

    /**
     * Pre-settlement compliance check.
     *
     * @param request abstracted settlement request derived from the
     *     incoming pacs.008 (or equivalent)
     * @return decision: allow or default-deny with reason code
     */
    @PostMapping("/settle/precheck")
    public ResponseEntity<SettlementDecision> precheck(@RequestBody @Valid SettlementRequest request) {
        SettlementDecision decision = orchestrator.evaluate(request);
        if (decision.isAllow()) {
            return ResponseEntity.ok(decision);
        }
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(decision);
    }

    /**
     * Audit trail of railgate decisions, for supervisory inspection.
     *
     * @return all recorded decisions in chronological order
     */
    @GetMapping("/audit")
    public ResponseEntity<List<RailgateAuditLog.AuditEntry>> audit() {
        return ResponseEntity.ok(auditLog.snapshot());
    }
}
