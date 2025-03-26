package gr.atc.urbreath.validation;

import gr.atc.urbreath.enums.PilotRole;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.apache.commons.lang3.EnumUtils;

public class PilotRoleValidator implements ConstraintValidator<ValidPilotRole, String> {

    @Override
    public boolean isValid(String pilotRole, ConstraintValidatorContext context) {
        if (pilotRole == null) {
            return true; // No Pilot Role Inserted
        }
        // Check string value against enum values
        return EnumUtils.isValidEnumIgnoreCase(PilotRole.class, pilotRole);
    }
}
