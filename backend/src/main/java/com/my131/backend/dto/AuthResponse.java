package com.my131.backend.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

// =========================
// 인증(로그인) 응답 DTO
// 서버 → 클라이언트로 반환되는 데이터
// JWT AccessToken, RefreshToken, 사용자 정보(UserDto) 포함
// =========================
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("refresh_token")
    private String refreshToken;

    // 로그인한 사용자 정보
    private UserDto user;
}
