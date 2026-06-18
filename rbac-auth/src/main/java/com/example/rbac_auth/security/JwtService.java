package com.example.rbac_auth.security;

import java.util.Date;

import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

@Service
public class JwtService {

    private static final String SECRET_KEY = "rbac-sentinel-enterprise-super-secret-key-signature";
    private static final String ISSUER = "rbac-sentinel-auth-service";
    private static final long EXPIRATION_TIME_MS = 2 * 60 * 60 * 1000; // 2 hours

    private final Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY);

    public String generateToken(String username, String role) {
        return JWT.create()
                .withIssuer(ISSUER)
                .withSubject(username)
                .withClaim("role", role)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME_MS))
                .sign(algorithm);
    }

    public DecodedJWT verifyToken(String token) {
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(ISSUER)
                .build();
        return verifier.verify(token);
    }

    public String getUsername(DecodedJWT jwt) {
        return jwt.getSubject();
    }

    public String getRole(DecodedJWT jwt) {
        return jwt.getClaim("role").asString();
    }
}
