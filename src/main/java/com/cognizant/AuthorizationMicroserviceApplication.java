package com.cognizant;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;

import com.cognizant.model.User;
import com.cognizant.repository.UserRepository;

@SpringBootApplication
@EnableFeignClients
public class AuthorizationMicroserviceApplication {
    @Autowired
    private UserRepository repository;

    //Initialization of users
    
    @PostConstruct
    public void initUser() {
	List<User> users = Stream.of(new User(101, "Kowsi", "12345678"), new User(102, "Kows", "password2")

	).collect(Collectors.toList());
	repository.saveAll(users);
    }

    public static void main(String[] args) {
	SpringApplication.run(AuthorizationMicroserviceApplication.class, args);
    }

}
