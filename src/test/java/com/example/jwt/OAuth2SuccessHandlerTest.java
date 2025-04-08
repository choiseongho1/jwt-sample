package com.example.jwt;

import com.example.jwt.entity.Role;
import com.example.jwt.entity.User;
import com.example.jwt.handler.OAuth2SuccessHandler;
import com.example.jwt.repository.RefreshTokenRepository;
import com.example.jwt.repository.UserRepository;
import com.example.jwt.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class OAuth2SuccessHandlerTest {

    @InjectMocks
    private OAuth2SuccessHandler oAuth2SuccessHandler;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private UserRepository userRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private Authentication authentication;

    @Mock
    private OAuth2User oAuth2User;

    @Captor
    private ArgumentCaptor<String> redirectCaptor;

    @Test
    void 로그인_성공시_자동회원가입_및_리다이렉트_토큰_포함() throws Exception {
        // given
        String email = "testuser@example.com";
        User user = new User(email, "", Role.ROLE_USER);
        String accessToken = "access-token";
        String refreshToken = "refresh-token";

        given(authentication.getPrincipal()).willReturn(oAuth2User);
        given(oAuth2User.getAttribute("email")).willReturn(email);
        given(userRepository.findByUsername(email)).willReturn(Optional.empty());
        given(userRepository.save(any())).willReturn(user);
        given(jwtUtil.generateToken(email, Role.ROLE_USER)).willReturn(accessToken);
        given(jwtUtil.generateRefreshToken(email)).willReturn(refreshToken);

        MockHttpServletResponse mockResponse = new MockHttpServletResponse();

        // when
        oAuth2SuccessHandler.onAuthenticationSuccess(request, mockResponse, authentication);

        // then
        String redirect = mockResponse.getRedirectedUrl();

        assertThat(redirect).contains("accessToken=" + accessToken);
        assertThat(redirect).contains("refreshToken=" + refreshToken);
        verify(userRepository).save(any());
        verify(refreshTokenRepository).save(eq(email), eq(refreshToken), anyLong());
    }
}
