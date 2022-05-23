package com.study.security;

import com.study.security.entity.Role;
import com.study.security.entity.User;
import com.study.security.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class SpringSecurityJwtRefreshTokensApplication {
    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityJwtRefreshTokensApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner run(UserService userService) {
        return args -> {
            userService.saveRole(new Role(null, "ROLE_USER"));
            userService.saveRole(new Role(null, "ROLE_MANAGER"));
            userService.saveRole(new Role(null, "ROLE_ADMIN"));
            userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

            userService.saveUser(new User(null, "Blaise Pascal", "blaise", "1234", new ArrayList<>()));
            userService.saveUser(new User(null, "Fibonacci", "fibonacci", "1234", new ArrayList<>()));
            userService.saveUser(new User(null, "Thalès de Milet ", "thales", "1234", new ArrayList<>()));
            userService.saveUser(new User(null, "Pythagoras", "pythagoras", "1234", new ArrayList<>()));

            userService.addRoleToUser("blaise", "ROLE_USER");
            userService.addRoleToUser("blaise", "ROLE_MANAGER");
            userService.addRoleToUser("fibonacci", "ROLE_MANAGER");
            userService.addRoleToUser("thales", "ROLE_ADMIN");
            userService.addRoleToUser("pythagoras", "ROLE_SUPER_ADMIN");
            userService.addRoleToUser("pythagoras", "ROLE_ADMIN");
            userService.addRoleToUser("pythagoras", "ROLE_USER");
        };
    }
}
