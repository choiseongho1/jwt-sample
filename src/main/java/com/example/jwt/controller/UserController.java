package com.example.jwt.controller;

import com.example.jwt.dto.LoginRequest;
import com.example.jwt.dto.SignupRequest;
import com.example.jwt.entity.User;
import com.example.jwt.repository.RefreshTokenRepository;
import com.example.jwt.repository.UserRepository;
import com.example.jwt.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;


    @PostMapping("/signup")
    public String signup(@RequestBody SignupRequest request) {
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new RuntimeException("이미 존재하는 사용자명입니다.");
        }

        String encodedPassword = passwordEncoder.encode(request.getPassword());
        userRepository.save(new User(
            request.getUsername(),
            encodedPassword,
            request.getRole()  // 전달된 권한으로 저장
        ));
        return "회원가입 성공";
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        User user = userRepository.findByUsername(request.getUsername())
        .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));

    if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
        throw new RuntimeException("비밀번호가 일치하지 않습니다.");
    }

    String accessToken = jwtUtil.generateToken(user.getUsername(), user.getRole());
    String refreshToken = jwtUtil.generateRefreshToken(user.getUsername());

    // Redis에 저장
    refreshTokenRepository.save(user.getUsername(), refreshToken, 1000L * 60 * 60 * 24 * 7); // 7일

    Map<String, String> tokens = new HashMap<>();
    tokens.put("accessToken", accessToken);
    tokens.put("refreshToken", refreshToken);

    return ResponseEntity.ok(tokens);
    }

    @GetMapping("/secured")
    public String securedEndpoint() {
        return "✅ 로그인만 하면 접근 가능한 API";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminEndpoint() {
        return "🔐 관리자만 접근 가능한 API";
    }
}