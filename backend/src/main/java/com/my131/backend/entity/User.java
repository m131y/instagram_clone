package com.my131.backend.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

// =========================
// User 엔티티 클래스
// Spring Security의 UserDetails를 구현하여
// 인증/인가에서 사용 가능
// =========================
@Entity
@Table(name = "users", indexes = {
        @Index(name = "idx_username", columnList = "username"), // username 인덱스 생성
        @Index(name = "idx_email", columnList = "email")        // email 인덱스 생성
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(name = "full_name")
    private String fullName;

    private String bio;

    @Column(name = "profile_image_url", columnDefinition = "TEXT")
    private String profileImageUrl;

    // 소셜 로그인 제공자 (예: GOOGLE, GITHUB 등)
    @Enumerated(EnumType.STRING)
    private AuthProvider provider;

    // 소셜 제공자에서 받은 고유 ID
    private String providerId;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    // 계정 활성화 여부
    private boolean enabled;

    // 엔티티 저장 전 실행되는 메서드
    // 기본적으로 계정을 활성화(true) 상태로 생성
    @PrePersist
    protected void onCreate() { enabled = true; }

    // =========================
    // UserDetails 인터페이스 구현
    // =========================

    // 사용자 권한(ROLE) 반환
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_USER"));
    }

    // 계정 활성화 여부 반환
    @Override
    public boolean isEnabled() { return enabled; }
}