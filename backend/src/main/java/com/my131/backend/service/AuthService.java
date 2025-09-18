package com.my131.backend.service;

import com.my131.backend.dto.AuthRequest;
import com.my131.backend.dto.AuthResponse;
import com.my131.backend.dto.RegisterRequest;
import com.my131.backend.dto.UserDto;
import com.my131.backend.entity.AuthProvider;
import com.my131.backend.entity.User;
import com.my131.backend.exception.AuthenticationException;
import com.my131.backend.exception.BadRequestException;
import com.my131.backend.exception.UserAlreadyExistsException;
import com.my131.backend.repository.UserRepository;
import com.my131.backend.security.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;         // DB 접근 (User CRUD)
    private final PasswordEncoder passwordEncoder;       // 비밀번호 암호화
    private final JwtService jwtService;                 // JWT 토큰 발급/검증
    private final AuthenticationManager authenticationManager; // 로그인 인증 관리 (여기서는 아직 사용 안함)

    // =========================
    // 회원가입 로직
    // =========================
    public AuthResponse register(RegisterRequest request) {
        // 1. username 중복 체크
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new UserAlreadyExistsException("Username already exist");
        }

        // 2. email 중복 체크
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException("Email already exist");
        }

        // 3. User 엔티티 생성
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .fullName(request.getFullName())
                .provider(AuthProvider.LOCAL) // 로컬 가입자로 표기
                .build();

        // 4. DB에 저장
        user = userRepository.save(user);

        // 5. JWT Access Token & Refresh Token 생성
        String jwtToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        // 6. 응답 DTO(AuthResponse) 반환
        return AuthResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .user(UserDto.fromEntity(user)) // 엔티티 → DTO 변환
                .build();
    }

    public AuthResponse authenticate(AuthRequest request) {
        try {
            log.info(" auth service : " , request);
            // email, username 둘 중 하나로 로그인
            String loginId = request.getEmail() != null ? request.getEmail() : request.getUsername();

            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginId,
                            request.getPassword()
                    )
            );
            User user = userRepository.findByEmail(loginId)
                    .or(() -> userRepository.findByUsername(loginId))
                    .orElseThrow(() -> new AuthenticationException("Authentication failed"));

            String jwtToken = jwtService.generateToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            return AuthResponse.builder()
                    .accessToken(jwtToken)
                    .refreshToken(refreshToken)
                    .user(UserDto.fromEntity(user))
                    .build();

        } catch (BadRequestException e) {
            throw new AuthenticationException("Invalid email or password");
        }
    }
}
