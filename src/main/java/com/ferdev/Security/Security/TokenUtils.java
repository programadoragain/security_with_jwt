package com.ferdev.Security.Security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class TokenUtils {
    private final static String SECRET_KEY= "4654ASDASDQW87EQW3ASDSDAD21";
    private final static long VALIDITY_TOKEN= 2592000l;

    public static String createToken(String nombre, String email){
        long expirationTime= VALIDITY_TOKEN * 1000l;
        Date expirationDate= new Date(System.currentTimeMillis() + expirationTime);

        Map<String, Object> extraInfomationInClaim= new HashMap<>();
        extraInfomationInClaim.put("nombre", nombre);

        return Jwts.builder()
                .setSubject(email)
                .setExpiration(expirationDate)
                .addClaims(extraInfomationInClaim)
                .signWith(Keys.hmacShaKeyFor(SECRET_KEY.getBytes()))
                .compact();
    }

    public static UsernamePasswordAuthenticationToken getAuthentication(String token){
        try{
            Claims claims= Jwts.parserBuilder()
                    .setSigningKey(SECRET_KEY.getBytes())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String email= claims.getSubject();

            return new UsernamePasswordAuthenticationToken(email, null, Collections.emptyList());
        }catch (Jwts)
    }
}
