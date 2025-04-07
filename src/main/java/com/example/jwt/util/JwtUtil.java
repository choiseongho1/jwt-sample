package com.example.jwt.util;

import com.example.jwt.entity.Role;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import org.springframework.stereotype.Component;
import jakarta.annotation.PostConstruct;
import javax.crypto.SecretKey;

@Component
public class JwtUtil {

    // 32자 이상이어야 함 (HMAC-SHA256 사용 시 최소 256비트 필요)
    private static final String SECRET_KEY = "ThisIsMySuperSecretKeyForJWTExample123!";

    // 토큰 만료 시간: 1시간
    private static final long EXPIRATION_TIME = 1000 * 60 * 60;

    // 리프레시 토큰 만료 시간 : 7일
    private static final long REFRESH_TIME = 1000 * 60 * 60 * 7;

    private SecretKey key;

    @PostConstruct
    public void init() {
        // 한 번만 키 초기화
        this.key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * JWT 토큰 생성
     */
    public String generateToken(String username, Role role) {
        return Jwts.builder()
            .setSubject(username)
            .claim("role", role.name()) // 권한 정보 포함
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
            .signWith(key)
            .compact();
    }

    /**
     * 토큰에서 username 추출 (검증 포함)
     */
    public String validateToken(String token) {
        return Jwts.parserBuilder()
            .setSigningKey(key) // 서명 키 설정
            .build()
            .parseClaimsJws(token) // 토큰 파싱 및 검증
            .getBody()
            .getSubject(); // username 반환
    }

    public SecretKey getKey() {
        return this.key;
    }

    public String generateRefreshToken(String username) {
        return Jwts.builder()
            .setSubject(username)
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + REFRESH_TIME)) // 7일
            .signWith(key)
            .compact();
    }
}

