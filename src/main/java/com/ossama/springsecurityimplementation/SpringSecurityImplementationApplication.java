package com.ossama.springsecurityimplementation;

import com.ossama.springsecurityimplementation.entities.AppRole;
import com.ossama.springsecurityimplementation.entities.AppUser;
import com.ossama.springsecurityimplementation.services.AccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.ArrayList;

@SpringBootApplication
public class SpringSecurityImplementationApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityImplementationApplication.class, args);
    }
    @Bean
    CommandLineRunner start(AccountService service){
        return args -> {
            service.addNewRole(new AppRole(null,"admin"));
            service.addNewRole(new AppRole(null,"user"));


            service.addNewUser(new AppUser(null,"user1","123",new ArrayList<>()));
            service.addNewUser(new AppUser(null,"user2","123",new ArrayList<>()));
           

            service.addRoleToUser("user1","admin");
            service.addRoleToUser("user1","user");
            service.addRoleToUser("user2","user");
        };
    }

}
