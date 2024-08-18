package com.example.jwt.jwt.demo.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_KEY = "fRS4sOdaHh9KtKv4fQzaiFS1z6+oQtPeD/00ARmBtESI92Q9FuKXqyzwxqfg8zJTfJl/+8wHwX8IyXJnmz4DyG92/NyijHYnFDwsFJu8Q5/l1mmGiTxX3G2iLGLLk8DSirGWvLY4QFcsuv++wLU7t5xlQ1idlQIqqXSfm2MHwg4dZp3lUNQ/rk8e9wJClGeVWyVYLfmL+EQCLhALdqUNf7aB/LxBfkcUfytgGwQvSsTn10lpukkh/7o9JjXG6VQIeqrdldaEa2aFiVD9Th15fHgh7B34y7pPtiNH2PUd245m1XGeYz6uY8qBBZzgGCXifnWde01DWIVV1H7ITxgs8TudEyNeSTwiH+amBObwWQQ=\n";


    public String extractUsername(String token) {
        return extractClaims(token, Claims::getSubject);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public <T> T extractClaims(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }

    public boolean isTokenValidate(String token,UserDetails userDetails){
        final String username=extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpirations(token).before(new Date());
    }

    private Date extractExpirations(String token) {
        return extractClaims(token,Claims::getExpiration);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignKey(), SignatureAlgorithm.ES256)
                .compact();
    }

    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);

    }
}
