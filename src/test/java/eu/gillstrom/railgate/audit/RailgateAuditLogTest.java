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

    @Test
    void fieldsFromTheGatekeeperAreBoundedAndCarryNoControlCharacters() {
        RailgateAuditLog auditLog = new RailgateAuditLog();
        auditLog.record(SettlementDecision.builder()
                .allow(false)
                .reasonCode("CERT_NOT_FOUND")
                .message("m")
                .transactionReference("TX\u001b[31mREF\u2028")
                .auditEntryId("A".repeat(10_000))
                .auditEntryHashHex("b".repeat(10_000))
                .build());

        var entry = auditLog.snapshot().get(0);
        assertThat(entry.gatekeeperAuditEntryId()).hasSize(RailgateAuditLog.MAX_FIELD_LENGTH);
        assertThat(entry.gatekeeperAuditEntryHashHex()).hasSize(RailgateAuditLog.MAX_FIELD_LENGTH);
        assertThat(entry.transactionReference()).isEqualTo("TX [31mREF ");

        auditLog.record(SettlementDecision.builder().allow(false).reasonCode("INTERNAL_ERROR")
                .transactionReference("T".repeat(10_000)).build());
        assertThat(auditLog.snapshot().get(1).transactionReference()).hasSize(RailgateAuditLog.MAX_FIELD_LENGTH);
    }

    @Test
    void sanitiseKeepsOrdinaryTextAndHonoursTheLimit() {
        assertThat(RailgateAuditLog.sanitise("abc", 2)).isEqualTo("ab");
        assertThat(RailgateAuditLog.sanitise("abc", 3)).isEqualTo("abc");
        assertThat(RailgateAuditLog.sanitise("a\tb\u0085c\u2029", 10)).isEqualTo("a b c ");
        assertThat(RailgateAuditLog.sanitise(null, 3)).isNull();
    }

    private static SettlementDecision denial(String reference) {
        return SettlementDecision.builder()
                .allow(false)
                .reasonCode("CERT_NOT_FOUND")
                .message("denied")
                .transactionReference(reference)
                .build();
    }

    private static long evictionWarnings(ListAppender<ILoggingEvent> appender) {
        return appender.list.stream()
                .filter(event -> event.getFormattedMessage().contains("discarding the oldest records"))
                .count();
    }

    @Test
    void theCapKeepsTheNewestTenThousandEntriesAndCountsTheDiscardedOnes() {
        RailgateAuditLog auditLog = new RailgateAuditLog();
        Logger logger = (Logger) LoggerFactory.getLogger(RailgateAuditLog.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            for (int i = 0; i < 10_000; i++) {
                auditLog.record(denial("TX-" + i));
            }
            assertThat(auditLog.health()).isEqualTo(new RailgateAuditLog.AuditLogHealth(10_000, 10_000, 0));
            assertThat(auditLog.getEvictedCount()).isZero();
            assertThat(auditLog.snapshot().get(0).transactionReference()).isEqualTo("TX-0");
            assertThat(evictionWarnings(appender)).isZero();

            auditLog.record(denial("TX-10000"));
            assertThat(auditLog.health()).isEqualTo(new RailgateAuditLog.AuditLogHealth(10_000, 10_000, 1));
            assertThat(auditLog.getEvictedCount()).isEqualTo(1);
            assertThat(auditLog.snapshot()).hasSize(10_000);
            assertThat(auditLog.snapshot().get(0).transactionReference()).isEqualTo("TX-1");
            assertThat(auditLog.snapshot().get(9_999).transactionReference()).isEqualTo("TX-10000");
            assertThat(evictionWarnings(appender)).isEqualTo(1);

            // One warning per thousand discarded records, not one per record.
            for (int i = 10_001; i < 11_000; i++) {
                auditLog.record(denial("TX-" + i));
            }
            assertThat(auditLog.getEvictedCount()).isEqualTo(1_000);
            assertThat(evictionWarnings(appender)).isEqualTo(1);
            auditLog.record(denial("TX-11000"));
            assertThat(auditLog.getEvictedCount()).isEqualTo(1_001);
            assertThat(evictionWarnings(appender)).isEqualTo(2);
        } finally {
            logger.detachAppender(appender);
        }
    }

    @Test
    void anAllowIsLoggedAtInfoAndADenialAtWarn() {
        RailgateAuditLog auditLog = new RailgateAuditLog();
        Logger logger = (Logger) LoggerFactory.getLogger(RailgateAuditLog.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            auditLog.record(SettlementDecision.builder()
                    .allow(true)
                    .reasonCode("ALLOWED")
                    .transactionReference("TX-A")
                    .build());
            auditLog.record(denial("TX-D"));

            assertThat(appender.list).hasSize(2);
            assertThat(appender.list.get(0).getLevel()).isEqualTo(ch.qos.logback.classic.Level.INFO);
            assertThat(appender.list.get(0).getFormattedMessage()).startsWith("Settlement ALLOWED: ref=TX-A");
            assertThat(appender.list.get(1).getLevel()).isEqualTo(ch.qos.logback.classic.Level.WARN);
            assertThat(appender.list.get(1).getFormattedMessage()).startsWith("Settlement DENIED: ref=TX-D");
        } finally {
            logger.detachAppender(appender);
        }
    }
}
