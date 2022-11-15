package com.dico.customercomplaint.user.controller;

import com.dico.customercomplaint.user.model.User;
import com.dico.customercomplaint.user.repository.UserRepository;
import com.dico.customercomplaint.user.service.RoleService;
import com.dico.customercomplaint.user.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.view.RedirectView;

@Controller
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private RoleService roleService;

    //Index route
    @GetMapping("")
    public String getHome(){
        return "index";
    }

    //Login route
    @GetMapping("/login")
    public String login(){
        return "/login";
    }

    //logout route
    @GetMapping("/logout")
    public String logout(){
        return "/login";
    }

    @GetMapping("/user")
    public String UserHome(){
        return "/user/index";
    }

    //Get all users route
    @GetMapping("/users")
    public String getAllUsers(Model model){
        model.addAttribute("users", userService.findAll());
        return "/user/users";
    }
    //Get single user by Id
    @GetMapping("/user/{op}/{id}")
    public String getSingleUser(@PathVariable Integer id, @PathVariable String op, Model model){
        User user = userService.findById(id);
        model.addAttribute("user", user);
        model.addAttribute("userRoles", roleService.getUserRoles(user));
        model.addAttribute("userNotRoles", roleService.getUserNotRoles(user));
        return "/user/" + op;
    }
    //Add New User
    @PostMapping("/user/addUser")
    public RedirectView addUser(User user, RedirectAttributes redir) {
        userService.save(user);
        RedirectView redirectView = new RedirectView("/login", true);
        redir.addFlashAttribute("message", "You have successfully registered a new user!");
        return redirectView;
    }

}
