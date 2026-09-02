package eu.gillstrom.railgate.model;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The constraints that decide whether a settlement request is accepted at all.
 *
 * <p>{@code SettlementController.precheck} takes {@code @Valid}, so a
 * violation here is a 400 from
 * {@code SettlementExceptionHandler.handleInvalidRequest} rather than a
 * settlement decision — the request never reaches the orchestrator. These
 * tests pin which requests that applies to.</p>
 */
class SettlementRequestValidationTest {

    private static ValidatorFactory factory;
    private static Validator validator;

    @BeforeAll
    static void openValidator() {
        factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @AfterAll
    static void closeValidator() {
        if (factory != null) {
            factory.close();
        }
    }

    private static Set<String> violatedProperties(SettlementRequest request) {
        return validator.validate(request).stream()
                .map(ConstraintViolation::getPropertyPath)
                .map(Object::toString)
                .collect(java.util.stream.Collectors.toSet());
    }

    @Test
    void aPayloadCarryingOnlyTheTransactionReferenceIsRejected() {
        // The minimal payload a caller can send. Until 1.4.0 both party-type
        // flags were primitives, so this deserialised to
        // debtorIsOrganization=false, creditorIsPrivatePerson=false — a
        // private-to-private transfer, which railgate passes through with
        // allow=true. The omission now fails validation instead.
        SettlementRequest request = SettlementRequest.builder()
                .transactionReference("UETR-12345")
                .build();

        assertThat(violatedProperties(request))
                .containsExactlyInAnyOrder("debtorIsOrganization", "creditorIsPrivatePerson");
    }

    @Test
    void aFullyClassifiedRequestPassesValidation() {
        SettlementRequest request = SettlementRequest.builder()
                .transactionReference("UETR-12345")
                .localInstrumentCode("SWISH")
                .debtorIsOrganization(true)
                .creditorIsPrivatePerson(true)
                .debtorBic("ESSESESS")
                .creditorBic("HANDSESS")
                .build();

        assertThat(validator.validate(request)).isEmpty();
    }

    @Test
    void aBlankTransactionReferenceIsRejected() {
        SettlementRequest request = SettlementRequest.builder()
                .transactionReference("  ")
                .debtorIsOrganization(true)
                .creditorIsPrivatePerson(true)
                .build();

        assertThat(violatedProperties(request)).contains("transactionReference");
    }

    @Test
    void anOverLongLocalInstrumentCodeIsRejected() {
        SettlementRequest request = SettlementRequest.builder()
                .transactionReference("UETR-12345")
                .localInstrumentCode("X".repeat(36))
                .debtorIsOrganization(true)
                .creditorIsPrivatePerson(true)
                .build();

        assertThat(violatedProperties(request)).contains("localInstrumentCode");
    }
}
