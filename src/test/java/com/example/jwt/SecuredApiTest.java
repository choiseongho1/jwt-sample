package com.example.jwt;

import com.example.jwt.entity.Role;
import com.example.jwt.entity.User;
import com.example.jwt.repository.UserRepository;
import com.example.jwt.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class SecuredApiTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    @BeforeEach
    void setUp() {
        User user = new User("user1", passwordEncoder.encode("1234"), Role.ROLE_USER);
        userRepository.save(user);
    }

    @Test
    void 인증된_사용자만_접근가능한_API_테스트() throws Exception {
        // 1. 토큰 생성
        String token = jwtUtil.generateToken("user1", Role.ROLE_USER);

        // 2. 요청
        mockMvc.perform(get("/api/secured")
                        .headers(TokenTestHelper.createAuthHeader(token)))
                .andExpect(status().isOk())
                .andExpect(content().string("✅ 로그인만 하면 접근 가능한 API"));
    }

    @Test
    void 토큰_없이_접근시_401_반환() throws Exception {
        mockMvc.perform(get("/api/secured"))
                .andExpect(status().isUnauthorized());
    }
}
