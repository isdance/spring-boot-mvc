package com.jeremy.fundamentals.dtos;

import com.jeremy.fundamentals.entities.Customer;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.BeanUtils;

import java.util.ArrayList;

@Getter
@Setter
public class UserResponse {
    private int Id;
    private String Name;
    private String Username;

    public static UserResponse fromUser(Customer user) {
        var response = new UserResponse();
        BeanUtils.copyProperties(user, response, new String[]{"password"});
        return response;
    }

    public static Iterable<UserResponse> fromUsers(Iterable<Customer> users) {
        ArrayList<UserResponse> responses = new ArrayList<UserResponse>();
        // do not return password to web
        for (var user : users) {
            var response = new UserResponse();
            BeanUtils.copyProperties(user, response, new String[]{"password"});
            responses.add(response);
        }
        return responses;
    }
}
