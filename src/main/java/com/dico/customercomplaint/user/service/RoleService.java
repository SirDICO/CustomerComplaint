package com.dico.customercomplaint.user.service;

import com.dico.customercomplaint.user.model.Role;
import com.dico.customercomplaint.user.model.User;
import com.dico.customercomplaint.user.repository.RoleRepository;
import com.dico.customercomplaint.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;

@Service
public class RoleService {

    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private UserRepository userRepository;

    //Get All Roles
    public List<Role>findAll(){
        return roleRepository.findAll();
    }
    public Role findById(int id){
        return roleRepository.findById(id).orElse(null);
    }
    //Delete Role
    public void DeleteRole(int id){
        roleRepository.deleteById(id);
    }

    //Update and Save also
    public void save(Role role){
        roleRepository.save(role);
    }

    //Assign Role to User
    public void assignUserRole(Integer userId, Integer roleId) {
        User user = userRepository.findById(userId).orElse(null);
        Role role = roleRepository.findById(roleId).orElse(null);
        Set<Role> userRoles = user.getRoles();
        userRoles.add(role);
        user.setRoles(userRoles);
        userRepository.save(user);
    }

    public void delete(Integer id){
        roleRepository.deleteById(id);
    }
    //Unassign Role to User
    public void unassignUserRole(Integer userId, Integer roleId) {
        User user = userRepository.findById(userId).orElse(null);
        user.getRoles().removeIf(x -> x.getId() == roleId);
        userRepository.save(user);
    }

    public Set<Role> getUserRoles(User user) {
        return user.getRoles();
    }

    public List<Role> getUserNotRoles(User user) {
        return roleRepository.getUserNotRoles(user.getId());
    }


}
