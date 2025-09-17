package com.my131.backend.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

// =========================
// 인증(로그인) 요청 DTO
// 클라이언트 → 서버로 전달되는 로그인 요청 데이터
// username 또는 email + password 조합으로 로그인 가능
// =========================
@Data
public class AuthRequest {
    // 사용자명 (옵션 - 이메일 대신 가능)
    private String username;

    // 이메일 (옵션 - username 대신 가능)
    private String email;

    @NotBlank(message = "Password is required")
    private String password;
}
