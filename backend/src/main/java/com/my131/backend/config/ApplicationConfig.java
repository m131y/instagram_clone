package com.my131.backend.config;

import com.my131.backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

// =========================
// Spring Security 설정 클래스
// 사용자 인증/비밀번호 암호화/AuthenticationManager 설정
// =========================
@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {
    private final UserRepository userRepository;

    // =========================
    // UserDetailsService Bean
    // - Spring Security에서 사용자 정보를 조회할 때 사용
    // - loginId 값이 숫자면 userId로 조회
    // - 숫자가 아니면 email → username 순으로 조회
    // =========================
    @Bean
    public UserDetailsService userDetailsService() {
        return loginId -> {
            try {
                // loginId가 숫자라면 userId 기반 조회
                Long userId = Long.parseLong(loginId);
                return userRepository.findById(userId)
                        .orElseThrow(() -> new UsernameNotFoundException("User not found with ID:  " + userId));
            } catch (NumberFormatException e) {
                // 숫자가 아니라면 email → username 순으로 조회
                return userRepository.findByEmail(loginId)
                        .or(() -> userRepository.findByUsername(loginId))
                        .orElseThrow(() -> new UsernameNotFoundException("User not found"));
            }
        };
    }

    // =========================
    // AuthenticationManager Bean
    // - Spring Security의 인증(Authentication) 과정을 총괄하는 인터페이스
    // - 로그인 시 전달된 사용자 정보(username/email/ID + password)를 검증
    // - 내부적으로 UserDetailsService + PasswordEncoder를 사용
    // - AuthenticationConfiguration에서 자동 생성된 AuthenticationManager를 가져와 Bean으로 등록
    // =========================
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    // =========================
    // PasswordEncoder Bean
    // - 비밀번호 암호화/검증에 사용
    // - BCrypt 해시 알고리즘 사용
    // =========================
    @Bean
    public PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }
}
