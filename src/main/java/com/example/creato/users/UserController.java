package com.example.creato.users;

import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @PostMapping("/register")
    public User register(@RequestBody User user) {
        return this.userRepository.save(user);
    }

    @GetMapping("inMemory")
    public User createFred() {
        User fred = new User();
        Role role = this.roleRepository.findByName("ADMIN");
        fred.setRole(role);
        fred.setEmail("frevirard@gmail.com");
        fred.setPassWord(new BCryptPasswordEncoder().encode("331093"));
        fred.setUserName("frevirard");
        fred.setAccountVerified(false);
        return this.userRepository.save(fred);
    }

    @GetMapping("/fred")
    public String getSomeString() {
        return "Hello StringBoy, need some baby oil ?";
    }

    @GetMapping("/createRoles")
    public String addRoles() {
        Role admin = new Role();
        admin.setName("ADMIN");
        Role user = new Role();
        user.setName("USER");
        this.roleRepository.save(admin);
        this.roleRepository.save(user);
        return "OK";
    }

}
