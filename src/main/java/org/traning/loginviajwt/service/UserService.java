package org.traning.loginviajwt.service;

import org.springframework.stereotype.Service;
import org.traning.loginviajwt.model.User;
import org.traning.loginviajwt.repository.UserRepository;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }


    public List<User> getAllUsers() {
        List<User> allUsers = new ArrayList<>();
        Iterable<User> all = userRepository.findAll();
        all.forEach(allUsers::add);
        return allUsers;
    }
}
