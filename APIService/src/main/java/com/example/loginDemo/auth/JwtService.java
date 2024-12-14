package com.example.loginDemo.auth;

import com.example.loginDemo.exception.ExpiredTokenException;
import com.example.loginDemo.exception.InvalidTokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.http.ResponseCookie;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
@RequiredArgsConstructor
public class JwtService {

    @Value("${security.secret.key}")
    private String secret_key;

    private final BlacklistService blacklistService;

    private static final long ACCESS_TOKEN_EXPIRATION = 1000 * 60 * 60; // 1 hour
    private static final long REFRESH_TOKEN_EXPIRATION = 1000 * 60 * 60 * 24 * 7; // 7 days
    public static final boolean REFRESH_TOKEN_HTTP_ONLY = true;
    public static final boolean REFRESH_TOKEN_SECURE = true;
    public static final String REFRESH_TOKEN_PATH = "/";

    public String extractUsername(String token) {
        try {
            return extractClaim(token, Claims::getSubject);
        } catch (ExpiredTokenException e) {
            throw new ExpiredTokenException("The token has expired.");
        } catch (Exception e) {
            throw new InvalidTokenException("Invalid token.");
        }
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateAccessToken(UserDetails userDetails, String role) {
        return generateAccessToken(new HashMap<>(), userDetails, "access", role);
    }

    public String generateAccessToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            String tokenType,
            String role
    ) {
        extraClaims.put("type", tokenType);
        extraClaims.put("role", role);
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRATION))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public ResponseCookie createRefreshTokenCookie(String refreshToken) {
        return ResponseCookie.from("refreshToken", refreshToken)
                .httpOnly(REFRESH_TOKEN_HTTP_ONLY)
                .secure(REFRESH_TOKEN_SECURE)
                .path(REFRESH_TOKEN_PATH)
                .maxAge(REFRESH_TOKEN_EXPIRATION)
                .build();
    }

    public String generateRefreshToken(UserDetails userDetails, String role) {
        return generateRefreshToken(new HashMap<>(), userDetails, "refresh", role);
    }

    public String generateRefreshToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            String tokenType,
            String role
    ) {
        extraClaims.put("type", tokenType);
        extraClaims.put("role", role);
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRATION))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        if (isTokenExpired(token)) {
            return false;
        }
        if (isTokenBlacklisted(token)) {
            return false;
        }

        String username = extractUsername(token);
        return username.equals(userDetails.getUsername());
    }

    protected boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    protected Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secret_key);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public boolean isTokenBlacklisted(String token) {
        return blacklistService.isTokenBlacklisted(token);
    }

    // Refresh Token 및 Access Token 유효성 검사 통합
    public boolean isTokenExpiredOrBlacklisted(String token, String tokenType) {
        if (isTokenExpired(token)) {
            throw new ExpiredTokenException(tokenType + " token is expired");
        }
        if (isTokenBlacklisted(token)) {
            throw new InvalidTokenException(tokenType + " token is blacklisted");
        }
        return false; // 유효한 토큰
    }
}
