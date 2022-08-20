package com.cognizant.controller;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
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
    private static final String BAD_CREDENTIALS_MESSAGE = "Invalid Username or Password";
    private static final String USER_NOT_CREATED_MESSAGE = "User Not Created. Try Again Later";

    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private CustomUserDetailService userDetailService;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserRepository userRepository;

    /**
     * @URL: http://localhost:8090/authenticate
     * 
     * @Data: [Admin] { "userName": "Kowsi", "password": "12345678" }
     * 
     * @param authRequest {userName, password}
     * 
     * @return token on successful login else return error message
     */

    @PostMapping("/authenticate")
    public ResponseEntity<String> login(@RequestBody AuthRequest authRequest) throws Exception {
	LOGGER.info("STARTED - User authentication");
	try {
	    Authentication authenticate = authenticationManager.authenticate(
		    new UsernamePasswordAuthenticationToken(authRequest.getUserName(), authRequest.getPassword()));
	    if (authenticate.isAuthenticated()) {
		LOGGER.info("Valid User detected");
	    }
	} catch (BadCredentialsException e) {
	    LOGGER.error("EXCEPTION - Bad Credentials");
	    return new ResponseEntity<>(BAD_CREDENTIALS_MESSAGE, HttpStatus.NOT_FOUND);
	}
	String token = jwtUtil.generateToken(authRequest.getUserName());
	LOGGER.info("END - Generated Token " + token.toString());
	return new ResponseEntity<>(token, HttpStatus.OK);
    }

    /**
     * Register new user
     * 
     * @URL: http://localhost:9090/register
     * 
     * @param user {userName, password}
     * 
     * @return new newly created user else return error message
     */

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody User user) throws Exception {
	LOGGER.info("STARTED - New User Registration");
	try {
	    User userDetails = userRepository.save(user);
	    return new ResponseEntity<>(userDetails, HttpStatus.CREATED);
	} catch (Exception e) {
	    LOGGER.error("EXCEPTION - New User Not Created");
	    return new ResponseEntity<>(USER_NOT_CREATED_MESSAGE, HttpStatus.INTERNAL_SERVER_ERROR);
	}

    }

    /**
     * Checks if the token is a valid administrator token
     * 
     * @URL: http://localhost:9090/authorize
     * 
     * @Header: [Authorization] = JWT Token
     * 
     * @param token
     * 
     * @return true if valid, else return false
     */

    @GetMapping("/authorize")
    public ResponseEntity<?> authorization(@RequestHeader("Authorization") String authToken) {

	LOGGER.info("STARTED - token authorization");
	String token = authToken.substring(7);

	UserDetails user = userDetailService.loadUserByUsername(jwtUtil.extractUsername(token));

	if (jwtUtil.validateToken(token, user)) {
	    LOGGER.info("END - token authorized");
	    return new ResponseEntity<>(true, HttpStatus.OK);
	} else {
	    LOGGER.info("END - Invalid token");
	    return new ResponseEntity<>(false, HttpStatus.UNAUTHORIZED);
	}

    }

    /**
     * @URL: http://localhost:9090/getAllUsers
     * 
     * @return all users
     */
    @GetMapping("/getAllUsers")
    public List<User> getAllDetail() {
	LOGGER.info("STARTED - getAllDetail");
	LOGGER.info("END - getAllDetail");
	return userRepository.findAll();

    }
}
