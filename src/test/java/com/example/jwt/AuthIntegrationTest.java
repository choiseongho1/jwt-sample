package com.example.jwt;

import com.example.jwt.entity.Role;
import com.example.jwt.entity.User;
import com.example.jwt.repository.RefreshTokenRepository;
import com.example.jwt.repository.UserRepository;
import com.example.jwt.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuthIntegrationTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired private UserRepository userRepository;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private JwtUtil jwtUtil;
    @Autowired private RefreshTokenRepository refreshTokenRepository;

    @BeforeEach
    void setUp() {
        // 유저, 관리자 등록
        userRepository.save(new User("user1", passwordEncoder.encode("pass123"), Role.ROLE_USER));
        userRepository.save(new User("admin1", passwordEncoder.encode("pass123"), Role.ROLE_ADMIN));
    }

    @Test
    void 로그인_성공시_토큰_반환() throws Exception {
        String json = """
            {
              "username": "user1",
              "password": "pass123"
            }
            """;

        mockMvc.perform(post("/api/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists());
    }

    @Test
    void 로그인_실패시_에러반환() throws Exception {
        String json = """
            {
              "username": "user1",
              "password": "wrong"
            }
            """;

        mockMvc.perform(post("/api/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.message").value("비밀번호가 일치하지 않습니다."));
    }

    @Test
    void 일반사용자_권한_접근가능_API() throws Exception {
        String token = jwtUtil.generateToken("user1", Role.ROLE_USER);

        mockMvc.perform(get("/api/secured")
                        .headers(TokenTestHelper.createAuthHeader(token)))
                .andExpect(status().isOk())
                .andExpect(content().string("✅ 로그인만 하면 접근 가능한 API"));
    }

    @Test
    void ROLE_USER_로_ADMIN_API_접근시_403() throws Exception {
        String token = jwtUtil.generateToken("user1", Role.ROLE_USER);

        mockMvc.perform(get("/api/admin")
                        .headers(TokenTestHelper.createAuthHeader(token)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void ROLE_ADMIN_으로_ADMIN_API_접근시_성공() throws Exception {
        String token = jwtUtil.generateToken("admin1", Role.ROLE_ADMIN);

        mockMvc.perform(get("/api/admin")
                        .headers(TokenTestHelper.createAuthHeader(token)))
                .andExpect(status().isOk())
                .andExpect(content().string("🔐 관리자만 접근 가능한 API"));
    }

    @Test
    void 토큰없이_접근시_401() throws Exception {
        mockMvc.perform(get("/api/secured"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void RefreshToken_재발급_성공() throws Exception {
        // RefreshToken 생성 & 저장
        String refreshToken = jwtUtil.generateRefreshToken("user1");
        refreshTokenRepository.save("user1", refreshToken, 1000L * 60 * 60 * 24);

        String json = """
            {
              "refreshToken": "%s"
            }
            """.formatted(refreshToken);

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists());
    }

    @Test
    void 로그아웃시_RefreshToken_삭제됨() throws Exception {
        // 저장 후 삭제 확인
        String refreshToken = jwtUtil.generateRefreshToken("user1");
        refreshTokenRepository.save("user1", refreshToken, 1000L * 60 * 60 * 24);
        String token = jwtUtil.generateToken("user1", Role.ROLE_USER);

        mockMvc.perform(delete("/api/auth/logout")
                        .headers(TokenTestHelper.createAuthHeader(token)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("로그아웃 완료"));

        assertThat(refreshTokenRepository.findByUsername("user1")).isEmpty();
    }
}
