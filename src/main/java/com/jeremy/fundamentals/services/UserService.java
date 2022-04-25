package com.jeremy.fundamentals.services;

import com.jeremy.fundamentals.dtos.UpsertUserInput;
import com.jeremy.fundamentals.entities.Customer;
import com.jeremy.fundamentals.repositories.UserRepository;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;
import java.util.Optional;

@Service
public class UserService implements IUserService {
    @PersistenceContext
    EntityManager em;

    @Autowired
    private PasswordEncoder passwordEncoder;

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
    public Customer findByUsername(String username) {
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<Customer> cq = cb.createQuery(Customer.class);
        Root<Customer> customerRoot = cq.from(Customer.class);

        Predicate stockCodePredicate = cb.equal(customerRoot.get("Username"), username);
        cq.where(stockCodePredicate);

        TypedQuery<Customer> query = em.createQuery(cq);
        var customer = query.getSingleResult();
        return customer;
    }

    @Override
    public Customer createUser(UpsertUserInput userDto) {
        var customerInDb = this.findByUsername(userDto.getUsername());
        if (customerInDb != null) {
            throw new IllegalArgumentException("There is an account with that username:" + customerInDb.getUsername());
        }
        BeanUtils.copyProperties(userDto, customerInDb, new String[]{"id"});
        customerInDb.setPassword(passwordEncoder.encode(userDto.getPassword()));
        return userRepository.save(customerInDb);
    }

    @Override
    public boolean updateUser(int id, UpsertUserInput user) {
        var userInDb = getUser(id);
        if (userInDb.isPresent()) {
            var targetUser = userInDb.get();
            BeanUtils.copyProperties(user, targetUser, new String[]{"id", "password"});
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
