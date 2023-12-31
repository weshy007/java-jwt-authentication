package com.example.JWTAuth;

import com.example.JWTAuth.entity.User;
import com.example.JWTAuth.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@SpringBootApplication
public class JwtAuthApplication {
	@Autowired
	private UserRepository userRepository;

	//Memory (h2) Database..
	@PostConstruct
	public void initUsers() {
		List<User> users = Stream.of(
				new User(1, "user1", "$2a$10$slYQmyNdGzTn7ZLBXBChFOC9f6kFjAqPhccnP6DxlWXx2lPk1C3G6", "email1@gmail.com"),
				new User(2, "user2", "$2a$10$slYQmyNdGzTn7ZLBXBChFOC9f6kFjAqPhccnP6DxlWXx2lPk1C3G6", "email2@gmail.com")
		).collect(Collectors.toList());
		userRepository.saveAll(users);
	}

	public static void main(String[] args) {
		SpringApplication.run(JwtAuthApplication.class, args);
	}

}
