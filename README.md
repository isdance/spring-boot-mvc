### 1. How to lazy join in Hibernate

There is a One-Many relationship between the `Customer` and `Invoice` entity classes. A customer can have many invoices.

`Customer` entity class

```java
package com.jeremy.fundamentals.entities;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.io.Serializable;

@Entity
@Table(name = "customers")
@Getter
@Setter
public class Customer implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // for `serial` type in postgres
    @Column(name="id")
    private Integer Id;

    @Column(name = "name", nullable = false)
    private String Name;
}

```

And `Invoice` entity class

```java
package com.jeremy.fundamentals.entities;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;

@Entity
@Table(name = "invoices")
@Getter
@Setter
public class Invoice implements Serializable {
    @Id
    @Column(name="stockcode", nullable = false)
    private String StockCode;

    @Column(name="quantity", nullable = false)
    private int Quantity;

    @Column(name="invoicedate", nullable = false)
    private Date InvoiceDate;

    @Column(name="unitprice", nullable = false)
    private Double UnitPrice;

    // must hide this if you defined a navigation property with JoinColumn
    // org.hibernate.MappingException: Repeated column in mapping for entity: com.jeremy.fundamentals.entities.Invoice column: customerid
    // @Column(name="customerid", nullable = false)
    // private int CustomerId;

    @Column(name="country", nullable = false)
    private String Country;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "customerid")
    private Customer Customer;
}

```

Note:

1. When creates the navigation property `customer` with JoinColumn `customerid`, needs to hide the original `private int CustomerId`. Otherwise will get error `org.hibernate.MappingException: Repeated column in mapping for entity: com.jeremy.fundamentals.entities.Invoice column: customerid`.
2. fetch Type can be set to `Eager`. But it it not optimized for performance.

And in order to work with `LAZY`, the most easiest way is `join fetch`. see below example.

```java
package com.jeremy.fundamentals.services;

import com.jeremy.fundamentals.entities.Invoice;
import com.jeremy.fundamentals.repositories.InvoiceRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;
import java.util.Optional;

@Service
public class InvoiceService implements IInvoiceService{
    @PersistenceContext
    EntityManager em;

    @Autowired
    private InvoiceRepository invoiceRepository;

    @Override
    public Optional<Invoice> findById(String id) {

        return invoiceRepository.findById(id);
    }

    public Iterable<Invoice> findAllById(String stockCode) {
    // in below query, the i.Customer and i.StockCode are property names of the Invoice class
    TypedQuery<Invoice> query = em.createQuery("Select i from Invoice i join fetch i.Customer where i.StockCode = :stockcode", Invoice.class)
            .setParameter("stockcode", stockCode);
    return query.getResultList();
}
}

```

If you don't use `join fetch`, will get below error `org.hibernate.LazyInitializationException: could not initialize proxy - XXX -no Session`.

The reason is well explained in this article [Fix LazyInitializationException: could not initialize proxy Error](could_not_initialize_proxy_Error.md)

If you are using Criteria then the same method can be written as given below-

```java
public Iterable<Invoice> findAllById(String stockCode) {
    CriteriaBuilder cb = em.getCriteriaBuilder();
    CriteriaQuery<Invoice> cq = cb.createQuery(Invoice.class);
    Root<Invoice> invoiceRoot = cq.from(Invoice.class);
    invoiceRoot.fetch("Customer"); // the `Customer` navigation property on Invoice entity class

    Predicate stockCodePredicate = cb.equal(invoiceRoot.get("StockCode"), stockCode);
    cq.where(stockCodePredicate);

    TypedQuery<Invoice> query = em.createQuery(cq);
    return query.getResultList();
}
```

Note:

1. The standard 'join' doesn't work with LAZY.

Below join does NOT work. Will throw same error as before. `Caused by: org.hibernate.LazyInitializationException: could not initialize proxy [com.jeremy.fundamentals.entities.Customer#14735] - no Session`

```java
 public Iterable<Invoice> findAllById(String stockCode) {
    CriteriaBuilder cb = em.getCriteriaBuilder();
    CriteriaQuery<Invoice> cq = cb.createQuery(Invoice.class);
    Root<Invoice> invoiceRoot = cq.from(Invoice.class);

    Predicate stockCodePredicate = cb.equal(invoiceRoot.get("StockCode"), stockCode);

    Join<Invoice, Customer> bJoin= invoiceRoot.join("Customer", JoinType.LEFT);
    bJoin.on(stockCodePredicate);

    TypedQuery<Invoice> query = em.createQuery(cq);
    return query.getResultList();
}
```

### 2. Validation in Spring Boot

[Validation with Spring Boot - the Complete Guide](https://reflectoring.io/bean-validation-with-spring-boot/)

1. Firstly annotate the input dto class

```java
package com.jeremy.fundamentals.dtos;

import com.jeremy.fundamentals.validators.IpAddress;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

@Getter
@Setter
public class UpsertUserInput {
    @NotNull(message = "Name is mandatory")
    @NotBlank(message = "Name is mandatory")
    @Pattern(regexp = "^[a-zA-Z]+(([',. -][a-zA-Z ])?[a-zA-Z]*)*$", message = "Invalid Name Format")
    private String name;
}
```

2. Then set up the @Valid annotation to the input dto object. And optionally, you can add a custom error handler for this controller class

```java
package com.jeremy.fundamentals.controller;

import com.jeremy.fundamentals.FundamentalsApplication;
import com.jeremy.fundamentals.dtos.UpsertUserInput;
import com.jeremy.fundamentals.entities.Customer;
import com.jeremy.fundamentals.services.UserService;
import org.apache.logging.log4j.message.FormattedMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

import static org.springframework.http.ResponseEntity.ok;

@RestController
@RequestMapping("users") // localhost:8080/users
public class UserController {

    private static final Logger log = LoggerFactory.getLogger(FundamentalsApplication.class);

    @Autowired
    private UserService _userService;

   // 'Get' Method omitted

    @PostMapping
    public ResponseEntity<Customer> createUser(@Valid @RequestBody UpsertUserInput customer) {
        return new ResponseEntity<Customer>(_userService.createUser(customer), HttpStatus.CREATED);
    }

    @PutMapping(value = "{id}")
    public ResponseEntity updateUser(@PathVariable int id, @Valid @RequestBody UpsertUserInput customer) {
        var isUpdated = _userService.updateUser(id, customer);

        if (!isUpdated) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    // 'Delete' Method omitted

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    ResponseEntity<String> handleMethodArgumentNotValidExceptionException(MethodArgumentNotValidException e) {
        StringBuilder sb = new StringBuilder();
        for (var error : e.getAllErrors()) {
            FormattedMessage fm = new FormattedMessage("{0}: {1}.", error.getObjectName(), error.getDefaultMessage());
            sb.append(fm);
        }
        return new ResponseEntity<>("Validation error(s): " + sb.toString(), HttpStatus.BAD_REQUEST);
    }
}

```

An example of response with errors:

```
Validation error(s): upsertUserInput: Invalid Name Format.
```

### How to add custom validator

[Validation with Spring Boot - the Complete Guide](https://reflectoring.io/bean-validation-with-spring-boot/)

Step 1: Create a @interface. The @ symbol denotes an annotation type definition. That means it is not really an interface, but rather a new annotation type to be used as a function modifier, such as @override.

```java
package com.jeremy.fundamentals.validators;

import javax.validation.Constraint;
import javax.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.RetentionPolicy.RUNTIME;



@Target({ FIELD })
@Retention(RUNTIME)
@Constraint(validatedBy = IpAddressValidator.class)
@Documented
public @interface IpAddress {
    String message() default "Invalid IP Address";

    Class<?>[] groups() default { };

    Class<? extends Payload>[] payload() default { };
}

```

Step 2: implementation of this class. No need to use `public` access modifier for this class. But it works the same if you add the `public` access modifier.

```java
package com.jeremy.fundamentals.validators;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class IpAddressValidator implements ConstraintValidator<IpAddress, String> {

    @Override
    public boolean isValid(String value, ConstraintValidatorContext constraintValidatorContext) {
        Pattern pattern =
                Pattern.compile("^([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})$");
        Matcher matcher = pattern.matcher(value);
        try {
            if (!matcher.matches()) {
                return false;
            } else {
                for (int i = 1; i <= 4; i++) {
                    int octet = Integer.valueOf(matcher.group(i));
                    if (octet > 255) {
                        return false;
                    }
                }
                return true;
            }
        } catch (Exception e) {
            return false;
        }
    }
}

```

Step 3: You can now use the `IpAddress` validation annotation like the others

```java
package com.jeremy.fundamentals.dtos;

import com.jeremy.fundamentals.validators.IpAddress;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

@Getter
@Setter
public class UpsertUserInput {
    @NotNull(message = "Name is mandatory")
    @NotBlank(message = "Name is mandatory")
    @Pattern(regexp = "^[a-zA-Z]+(([',. -][a-zA-Z ])?[a-zA-Z]*)*$", message = "Invalid Name Format")
    @IpAddress
    private String name;
}

```
