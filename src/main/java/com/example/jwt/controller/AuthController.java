package com.example.jwt.controller;

import com.example.jwt.dto.RefreshTokenRequest;
import com.example.jwt.entity.User;
import com.example.jwt.repository.RefreshTokenRepository;
import com.example.jwt.repository.UserRepository;
import com.example.jwt.util.JwtUtil;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();

        // 1. refreshToken 유효성 검사 및 사용자명 추출
        String username;
        try {
            username = Jwts.parserBuilder()
                    .setSigningKey(jwtUtil.getKey())
                    .build()
                    .parseClaimsJws(refreshToken)
                    .getBody()
                    .getSubject();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("message", "유효하지 않은 Refresh Token입니다."));
        }

        // 2. Redis에서 저장된 refreshToken과 비교
        String storedToken = refreshTokenRepository.findByUsername(username).orElse(null);
        if (storedToken == null || !storedToken.equals(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("message", "저장된 토큰과 일치하지 않습니다."));
        }

        // 3. 사용자 정보로 새 Access Token 발급
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("사용자 없음"));

        String newAccessToken = jwtUtil.generateToken(user.getUsername(), user.getRole());

        return ResponseEntity.ok(Collections.singletonMap("accessToken", newAccessToken));
    }

    @DeleteMapping("/logout")
    public ResponseEntity<?> logout() {
        // 1. SecurityContext에 저장된 사용자 정보 확인
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("message", "인증되지 않은 사용자입니다."));
        }

        String username = authentication.getName();

        // 2. Redis에서 Refresh Token 삭제
        refreshTokenRepository.deleteByUsername(username);
    
        return ResponseEntity.ok(Collections.singletonMap("message", "로그아웃 완료"));
    }
}