package com.example.jwt;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

public class TokenTestHelper {

    public static HttpHeaders createAuthHeader(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }
}