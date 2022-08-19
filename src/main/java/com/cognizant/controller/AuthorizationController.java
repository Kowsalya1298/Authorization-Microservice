package com.cognizant.controller;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import com.cognizant.exception.ResourceNotFound;
import com.cognizant.model.AuthRequest;
import com.cognizant.model.User;
import com.cognizant.repository.UserRepository;
import com.cognizant.service.CustomUserDetailService;
import com.cognizant.util.JwtUtil;

@RestController
public class AuthorizationController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationController.class);
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private CustomUserDetailService userDetailService;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserRepository userRepository;

    // starting message

    @GetMapping("/")
    public ResponseEntity<String> welcome() {
	LOGGER.info("STARTED authorization microservice welcome");
	LOGGER.info("END - authorization microservice welcome");
	return ResponseEntity.ok("Wecome to security application");
    }

    // Authenticate user and generate token

    @PostMapping("/authenticate")
    public ResponseEntity<String> generateToken(@RequestBody AuthRequest authRequest) throws Exception {
	LOGGER.info("STARTED - User authentication");
	try {
	    authenticationManager.authenticate(
		    new UsernamePasswordAuthenticationToken(authRequest.getUserName(), authRequest.getPassword()));

	} catch (Exception e) {
	    LOGGER.error("EXCEPTION - User authentication");
	    throw new ResourceNotFound("User not found");
	}

	LOGGER.info("END - generateToken");
	return ResponseEntity.ok(jwtUtil.generateToken(authRequest.getUserName()));
    }

    //Register new user
    
    @PostMapping("/register")
    public User register(@RequestBody User user) throws Exception {
	LOGGER.info("STARTED - generateToken");
	try {
	    User userDetails = userRepository.save(user);
	    return userDetails;
	} catch (Exception e) {
	    LOGGER.error("EXCEPTION - generateToken");
	    throw new ResourceNotFound("user not saved");
	}

    }

    // validtiion of the generated jwt token to access '/authorize' endpoint

    @GetMapping("/authorize")
    public ResponseEntity<?> authorization(@RequestHeader("Authorization") String token1) {

	LOGGER.info("STARTED - authorization");
	String token = token1.substring(7);

	UserDetails user = userDetailService.loadUserByUsername(jwtUtil.extractUsername(token));

	if (jwtUtil.validateToken(token, user)) {
	    LOGGER.info("END - authorization");
	    return new ResponseEntity<>(true, HttpStatus.OK);
	} else {
	    LOGGER.info("END - authorization");
	    return new ResponseEntity<>(false, HttpStatus.FORBIDDEN);
	}

    }

    @GetMapping("/getAll")
    public List<User> getAllDetail() {
	LOGGER.info("STARTED - getAllDetail");
	LOGGER.info("END - getAllDetail");
	return userRepository.findAll();

    }
}
