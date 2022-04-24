package com.jeremy.fundamentals.validators;

import javax.validation.Constraint;
import javax.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;


/*
* The @ symbol denotes an annotation type definition.
* That means it is not really an interface, but rather a new annotation type
* to be used as a function modifier, such as @override.
*/
@Target({ FIELD })
@Retention(RUNTIME)
@Constraint(validatedBy = IpAddressValidator.class)
@Documented
public @interface IpAddress {
    String message() default "Invalid IP Address";

    Class<?>[] groups() default { };

    Class<? extends Payload>[] payload() default { };
}
