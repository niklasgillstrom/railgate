package eu.gillstrom.railgate.audit;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import eu.gillstrom.railgate.model.SettlementDecision;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import static org.assertj.core.api.Assertions.assertThat;

class RailgateAuditLogTest {

    @Test
    void gatekeeperAuditEntryIdCannotForgeLogLines() {
        RailgateAuditLog auditLog = new RailgateAuditLog();
        Logger logger = (Logger) LoggerFactory.getLogger(RailgateAuditLog.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            auditLog.record(SettlementDecision.builder()
                    .allow(true)
                    .reasonCode("ALLOWED")
                    .message("Cryptographic verification passed")
                    .transactionReference("TXREF-LOG")
                    .auditEntryId("AE-1\r\nINFO Settlement ALLOWED: ref=FORGED")
                    .build());

            assertThat(auditLog.snapshot()).hasSize(1);
            assertThat(auditLog.snapshot().get(0).gatekeeperAuditEntryId())
                    .doesNotContain("\r", "\n")
                    .startsWith("AE-1");
            assertThat(appender.list).isNotEmpty();
            assertThat(appender.list).allSatisfy(event ->
                    assertThat(event.getFormattedMessage()).doesNotContain("\r", "\n"));
        } finally {
            logger.detachAppender(appender);
        }
    }
}
