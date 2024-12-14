package com.example.loginDemo.auth;

import com.example.loginDemo.dto.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final JwtService jwtService;
    private final LogoutService logoutService;
    private final UserDetailsService userDetailsService;

    //회원가입
    @PostMapping("/register")
    public ResponseEntity<Object> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    //로그인
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
        AuthenticationResponse authResponse = authService.authenticate(request);
        ResponseCookie refreshCookie = jwtService.createRefreshTokenCookie(authResponse.getRefreshToken());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body((AuthenticationResponse) Map.of("accessToken", authResponse.getAccessToken()));
    }

    // 로그아웃
    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @RequestHeader(name = "Authorization", required = false) String accessToken,
            @CookieValue(name = "refreshToken", required = false) String refreshToken) {
        if (refreshToken == null) {
            return ResponseEntity.status(400).body(Map.of("message", "Refresh Token is missing"));
        }

        if (accessToken == null || !accessToken.startsWith("Bearer ")) {
            return ResponseEntity.status(400).body(Map.of("message", "Access Token is missing or invalid"));
        }

        // Access Token에서 'Bearer ' 제거
        accessToken = accessToken.substring(7);

        try {
            // 로그아웃 처리
            logoutService.logout(accessToken, refreshToken);
            return ResponseEntity.ok(Map.of("message", "Successfully logged out"));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("message", "Logout failed: " + e.getMessage()));
        }
    }


    //회원 탈퇴
    @DeleteMapping("/delete-account")
    public ResponseEntity<Map<String, String>> deleteAccount(@RequestHeader("Authorization") String accessToken) {
        accessToken = extractToken(accessToken);

        // Access Token 유효성 확인
        jwtService.isTokenExpiredOrBlacklisted(accessToken, "access");

        Map<String, String> response = authService.deleteAccount(accessToken);
        return ResponseEntity.ok(response);
    }

    //access token 갱신
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshAccessToken(@CookieValue(name = "refreshToken", required = false) String refreshToken) {
        if (refreshToken == null) {
            return ResponseEntity.status(400).body(Map.of("message", "Refresh Token is missing"));
        }

        // Refresh Token 검증
        jwtService.isTokenExpiredOrBlacklisted(refreshToken, "refresh");

        // 사용자 정보 추출
        String userEmail = jwtService.extractUsername(refreshToken);
        UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);

        // 새로운 Access Token 및 Refresh Token 생성
        String newAccessToken = jwtService.generateAccessToken(userDetails, userDetails.getAuthorities().toString());
        String newRefreshToken = jwtService.generateRefreshToken(userDetails, userDetails.getAuthorities().toString());
        ResponseCookie refreshCookie = jwtService.createRefreshTokenCookie(newRefreshToken);

        // Access Token 반환 및 새로운 Refresh Token을 쿠키로 전달
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(Map.of("accessToken", newAccessToken));
    }

    //methods

    private String extractToken(String token) {
        return token.substring(7); // Assuming "Bearer " prefix
    }
}
