package gr.atc.urbreath.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = PilotRoleValidator.class)
@Target({ElementType.PARAMETER, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidPilotRole {
    String message() default "Invalid pilot role inserted. Only 'USER', 'DATA_SCIENTIST', 'ADMIN' or 'SUPER_ADMIN' are valid";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}