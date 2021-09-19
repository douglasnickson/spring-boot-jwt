package com.authentication.jwt.authenticationjwt;

import java.util.ArrayList;

import com.authentication.jwt.authenticationjwt.model.Role;
import com.authentication.jwt.authenticationjwt.model.User;
import com.authentication.jwt.authenticationjwt.service.UserService;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class AuthenticationjwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthenticationjwtApplication.class, args);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService) {
		return args -> {
			userService.saveRole(new Role(null, "ROLE_USER"));
			userService.saveRole(new Role(null, "ROLE_MANAGER"));
			userService.saveRole(new Role(null, "ROLE_ADMIN"));
			userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

			userService.saveUser(new User(null, "Douglas Nickson", "douglasnickson", "1234", new ArrayList<>()));
			userService.saveUser(new User(null, "Elen Vitória", "elenvitoria", "1234", new ArrayList<>()));

			userService.addRoleToUser("douglasnickson", "ROLE_ADMIN");
			userService.addRoleToUser("douglasnickson", "ROLE_SUPER_ADMIN");
			userService.addRoleToUser("douglasnickson", "ROLE_MANAGER");
			userService.addRoleToUser("elenvitoria", "ROLE_USER");
		};
	}

}
