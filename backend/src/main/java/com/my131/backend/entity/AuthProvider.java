package com.my131.backend.entity;

// =========================
// AuthProvider (인증 제공자 구분 Enum)
// 사용자가 어떤 방식으로 가입/로그인했는지 구분하기 위함
// =========================
public enum AuthProvider {
    LOCAL,   // 자체 회원가입/로그인 (일반 계정)
    GOOGLE,  // 구글 OAuth2 로그인
    GITHUB   // 깃허브 OAuth2 로그인
}
