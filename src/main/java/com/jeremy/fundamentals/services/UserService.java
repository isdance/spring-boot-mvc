package com.jeremy.fundamentals.services;

import com.jeremy.fundamentals.dtos.UpsertUserInput;
import com.jeremy.fundamentals.entities.Customer;
import com.jeremy.fundamentals.repositories.UserRepository;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService implements IUserService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public Iterable<Customer> getUsers() {
        return userRepository.findAll();
    }

    @Override
    public Optional<Customer> getUser(int id) {
        return userRepository.findById(id);
    }

    @Override
    public Customer createUser(UpsertUserInput user) {
        var targetUser = new Customer();
        BeanUtils.copyProperties(user, targetUser, new String[]{"id"});
        return userRepository.save(targetUser);
    }

    @Override
    public boolean updateUser(int id, UpsertUserInput user) {
        var userInDb = getUser(id);
        if (userInDb.isPresent()) {
            var targetUser = userInDb.get();
            BeanUtils.copyProperties(user, targetUser, new String[]{"id"});
            userRepository.save(targetUser);
            return true;
        }
        return false;
    }

    @Override
    public boolean deleteUser(int id) {
        if (userRepository.existsById(id)) {
            userRepository.deleteById(id);
            return true;
        }
        return false;
    }
}
