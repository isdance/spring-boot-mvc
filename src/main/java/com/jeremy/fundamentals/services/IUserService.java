package com.jeremy.fundamentals.services;

import com.jeremy.fundamentals.dtos.UpsertUserInput;
import com.jeremy.fundamentals.entities.Customer;

import java.util.Optional;

public interface IUserService {

     Iterable<Customer> getUsers();
     
     Optional<Customer> getUser(int id);

     Customer findByUsername(String username);

     Customer createUser(UpsertUserInput user);

     boolean updateUser(int id, UpsertUserInput user);

     boolean deleteUser(int id);
}
