package com.example.jwt.handler;

import com.example.jwt.entity.Role;
import com.example.jwt.entity.User;
import com.example.jwt.repository.RefreshTokenRepository;
import com.example.jwt.repository.UserRepository;
import com.example.jwt.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        // ✅ 구글 이메일 정보 가져오기
        String email = oAuth2User.getAttribute("email");

        // ✅ DB에 사용자 없으면 자동 회원가입 (기본 ROLE_USER)
        User user = userRepository.findByUsername(email)
            .orElseGet(() -> {
                User newUser = new User(email, "", Role.ROLE_USER);
                return userRepository.save(newUser);
            });

        // ✅ JWT 발급
        String accessToken = jwtUtil.generateToken(user.getUsername(), user.getRole());
        String refreshToken = jwtUtil.generateRefreshToken(user.getUsername());

        // ✅ Redis 저장
        refreshTokenRepository.save(user.getUsername(), refreshToken, 1000L * 60 * 60 * 24 * 7); // 7일

        // ✅ 토큰을 쿼리 파라미터로 리다이렉트 (또는 쿠키 사용 가능)
        String redirectUrl = UriComponentsBuilder.fromUriString("http://localhost:3000/oauth2/callback")
            .queryParam("accessToken", accessToken)
            .queryParam("refreshToken", refreshToken)
            .build().toUriString();

        response.sendRedirect(redirectUrl);
    }
}