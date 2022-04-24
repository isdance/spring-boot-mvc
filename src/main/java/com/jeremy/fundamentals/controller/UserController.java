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

    @GetMapping(
            consumes = {MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE},
            produces = {MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE})
    public ResponseEntity<Iterable<Customer>> getUsers() {
        return ok().body(_userService.getUsers());
    }

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

    @DeleteMapping(value = "{id}")
    public ResponseEntity deleteUser(@PathVariable int id) {
        var isRemoved = _userService.deleteUser(id);
        if (!isRemoved) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }

        return new ResponseEntity<>(id, HttpStatus.OK);
    }

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
