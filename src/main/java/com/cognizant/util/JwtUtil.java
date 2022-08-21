package com.cognizant.util;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * @author 889068
 *
 */
@Service
public class JwtUtil {
	
	 private String secret_key = "secret";

	    /**
	     * @param token
	     * @return
	     */
	    public String extractUsername(String token) {
	        return extractClaim(token, Claims::getSubject);
	    }

	    /**
	     * @param token
	     * @return expirattion date and time
	     */
	    public Date extractExpiration(String token) {
	        return extractClaim(token, Claims::getExpiration);
	    }

	    /**
	     * @param <T>
	     * @param token
	     * @param claimsResolver
	     * @return
	     */
	    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
	        final Claims claims = extractAllClaims(token);
	        return claimsResolver.apply(claims);
	    }
	    private Claims extractAllClaims(String token) {
	        return Jwts.parser().setSigningKey(secret_key).parseClaimsJws(token).getBody();
	    }

	    /**
	     * @param token
	     * @return true if token expired
	     */
	    private Boolean isTokenExpired(String token) {
	        return extractExpiration(token).before(new Date());
	    }
	    
	    /**
	     * @param username
	     * @return jwt token
	     */
	    public String generateToken(String username) {
	        Map<String, Object> claims = new HashMap<>();
	        return createToken(claims, username);
	    }

	    
	    /**
	     * @param claims
	     * @param subject
	     * @return  token based on HS256 algorithm using the secret key
	     */
	    private String createToken(Map<String, Object> claims, String subject) {

	        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
	                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
	                .signWith(SignatureAlgorithm.HS256, secret_key).compact();
	    }

	    /**
	     * @param token
	     * @param userDetails
	     * @return true if token is valid
	     */
	    public Boolean validateToken(String token, UserDetails userDetails) {
	        final String username = extractUsername(token);
	        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	    }

}
