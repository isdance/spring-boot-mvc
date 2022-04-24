package com.jeremy.fundamentals.repositories;

import com.jeremy.fundamentals.entities.Customer;
import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<Customer, Integer> {
}
