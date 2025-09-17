package com.my131.backend.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

// =========================
// 사용자 중복 예외 처리 클래스
// 동일한 username/email이 이미 존재할 경우 발생
// HTTP 상태 코드: 409 Conflict 반환
// =========================
@ResponseStatus(HttpStatus.CONFLICT) // 예외 발생 시 409 응답
public class UserAlreadyExistsException extends RuntimeException {
    // 예외 메시지를 부모 클래스(RuntimeException)에 전달
    public UserAlreadyExistsException(String message) { super(message); }
}
