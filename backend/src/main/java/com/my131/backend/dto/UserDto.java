package com.my131.backend.dto;

import com.my131.backend.entity.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

// =========================
// UserDto 클래스
// 엔티티(User) → DTO 변환용
// 클라이언트에 불필요한 정보(비밀번호 등)를
// 노출하지 않도록 가공해서 반환
// =========================
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {
    private Long id;
    private String username;
    private String email;
    private String fullName;
    private String bio;
    private String profileImageUrl;

    // user -> UserDto로 변형
    public static UserDto fromEntity(User user) {
        return UserDto.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .fullName(user.getFullName())
                .bio(user.getBio())
                .profileImageUrl(user.getProfileImageUrl())
                .build();
    }
}