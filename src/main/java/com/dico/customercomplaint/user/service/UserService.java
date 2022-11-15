package com.dico.customercomplaint.user.service;

import com.dico.customercomplaint.user.model.User;
import com.dico.customercomplaint.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder encoder;

    //Get all users
    public List<User> findAll(){
        return userRepository.findAll();
    }

    //Get by username
    public User findByUsername(String username){
         User user = userRepository.findByUsername(username);
         return user;
    }

    //Get User By Id
    public User findById(Integer id){
        return userRepository.findById(id).orElse(null);
    }

    //Delete A User
    public void deleteUser(Integer id){
        userRepository.deleteById(id);
    }

    //Update user and Save new user also
    public void save(User user){
        user.setPassword(encoder.encode(user.getPassword()));
        userRepository.save(user);
    }
}
