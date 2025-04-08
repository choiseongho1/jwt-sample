package com.example.jwt;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class OAuthPropertyLogger {

    @Value("${CLIENT_ID}")
    private String clientId;

    @Value("${CLIENT_SECRET}")
    private String clientSecret;

    @PostConstruct
    public void logOAuthProperties() {
        System.out.println("[OAuth2 설정 확인]");
        System.out.println("CLIENT_ID: " + clientId);
        System.out.println("CLIENT_SECRET: " + clientSecret);
    }
}