package com.example.loginDemo.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService {

    private final JwtService jwtService;
    private final BlacklistService blacklistService;

    public void logout(String accessToken, String refreshToken) {
        try {
            long accessTokenExpiration = Math.max(jwtService.extractExpiration(accessToken).getTime() - System.currentTimeMillis(), 0);
            long refreshTokenExpiration = Math.max(jwtService.extractExpiration(refreshToken).getTime() - System.currentTimeMillis(), 0);

            blacklistService.addToBlacklist(accessToken, accessTokenExpiration, "logout");
            blacklistService.addToBlacklist(refreshToken, refreshTokenExpiration, "logout");
        } catch (Exception e) {
            throw new RuntimeException("Failed to blacklist tokens during logout: " + e.getMessage());
        }
    }
}