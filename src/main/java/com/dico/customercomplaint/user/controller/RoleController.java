package com.dico.customercomplaint.user.controller;

import com.dico.customercomplaint.user.model.Role;
import com.dico.customercomplaint.user.model.User;
import com.dico.customercomplaint.user.service.RoleService;
import com.dico.customercomplaint.user.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@Controller
public class RoleController {
    @Autowired
    private RoleService roleService;

    @Autowired
    private UserService userService;

    @GetMapping("/user/roles")
    public String parameters(Model model) {
        List<Role> roles = roleService.findAll();
        model.addAttribute("roles", roles);
        return "user/roles";
    }

    @GetMapping("/user/roleEdit/{id}")
    public String editRole(@PathVariable Integer id, Model model) {
        Role role = roleService.findById(id);
        model.addAttribute("userRole", role);
        return "user/roleEdit";
    }
    @GetMapping("/user/addRole")
    public String addRole() {
        return "/user/addRole";
    }

    @PostMapping("/user/addRole")
    public String save(Role role) {
        roleService.save(role);
        return "redirect:/user/roles";
    }
    //The op parameter is either Edit or Details
//    @GetMapping("/user/role/{id}")
//    public String editRole(@PathVariable Integer id, Model model){
//        Role role = roleService.findById(id);
//        model.addAttribute("roles", role);
//        return "/parameters/country";
//    }

    @RequestMapping(value = "/user/role/delete/{id}", method = {RequestMethod.DELETE, RequestMethod.GET})
    public String delete(@PathVariable Integer id) {
        roleService.delete(id);
        return "redirect:/user/roles";
    }

    @RequestMapping("/user/role/assign/{userId}/{roleId}")
    public String assignRole(@PathVariable Integer userId,
                             @PathVariable Integer roleId) {
        roleService.assignUserRole(userId, roleId);
        return "redirect:/user/userEdit/" + userId;
    }

    @RequestMapping("/user/role/unassign/{userId}/{roleId}")
    public String unassignRole(@PathVariable Integer userId,
                               @PathVariable Integer roleId) {
        roleService.unassignUserRole(userId, roleId);
        return "redirect:/user/userEdit/" + userId;
    }
}
