package com.example.jwt.repository;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Repository
public class RefreshTokenRepository {

    private static final String PREFIX = "RT:";

    private final RedisTemplate<String, String> redisTemplate;

    public RefreshTokenRepository(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void save(String username, String refreshToken, long expirationMillis) {
        redisTemplate.opsForValue().set(PREFIX + username, refreshToken, expirationMillis, TimeUnit.MILLISECONDS);
    }

    public Optional<String> findByUsername(String username) {
        String token = redisTemplate.opsForValue().get(PREFIX + username);
        return Optional.ofNullable(token);
    }

    public void deleteByUsername(String username) {
        redisTemplate.delete(PREFIX + username);
    }
}