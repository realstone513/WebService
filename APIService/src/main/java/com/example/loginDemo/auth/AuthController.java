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
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request){
        return ResponseEntity.ok(authService.authenticate(request));
    }

    // 로그아웃
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String accessToken,
                                    @CookieValue(name = "refreshToken", required = false) String refreshToken) {
        if (refreshToken == null) {
            return ResponseEntity.status(400).body(Map.of(
                    "message", "Refresh Token is missing in cookies"
            ));
        }

        try {
            accessToken = extractToken(accessToken);
            logoutService.logout(accessToken, refreshToken);
            return ResponseEntity.ok("Successfully logged out");
        } catch (Exception e) {
            return ResponseEntity.status(400).body(Map.of(
                    "message", "Logout failed: " + e.getMessage()
            ));
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
    public ResponseEntity<Map<String, String>> refreshAccessToken(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");

        //만료된 refresh token의 경우
        jwtService.isTokenExpiredOrBlacklisted(refreshToken, "refresh");

        String userEmail = jwtService.extractUsername(refreshToken);
        UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);

        String newAccessToken = jwtService.generateAccessToken(userDetails, userDetails.getAuthorities().toString());
        String newRefreshToken = jwtService.generateRefreshToken(userDetails, userDetails.getAuthorities().toString());

        // JwtService를 사용하여 Refresh Token 쿠키 생성
        ResponseCookie refreshCookie = jwtService.createRefreshTokenCookie(newRefreshToken);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(Map.of("accessToken", newAccessToken));
    }

    //methods

    private String extractToken(String token) {
        return token.substring(7); // Assuming "Bearer " prefix
    }



}
