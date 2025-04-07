package com.example.jwt.dto;

import com.example.jwt.entity.Role;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignupRequest {
    private String username;
    private String password;
    private Role role;  // "ROLE_USER" or "ROLE_ADMIN"
}