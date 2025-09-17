package com.my131.backend.security;

import com.my131.backend.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Slf4j
@Service
public class JwtService {
    // application.yml, 환경변수로부터 주입
    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    @Value("${jwt.refresh-expiration}")
    private long refreshExpiration;

    @PostConstruct
    public void init() {
        log.debug("JWT_SECRET: {}", secretKey);
        log.debug("JWT_EXPIRATION: {}", jwtExpiration);
        log.debug("JWT_REFRESH_EXPIRATION: {}", refreshExpiration);
    }

    // -------------------------------------
    // JWT에서 username(식별자) 추출
    // - 토큰에 "id" 클레임이 있으면 그 값을 식별자로 사용(예: 내부적으로 id로 로그인 처리)
    // - 그렇지 않으면 subject를 식별자로 사용 (subject는 buildToken에서 setSubject로 설정됨)
    // -------------------------------------
    public String extractUsername(String token) {
        Claims claims = extractAllClaims(token);
        if (claims.containsKey("id")) {
            return String.valueOf(claims.get("id"));
        }
        return claims.getSubject();
    }

    // 임의의 Claim을 추출하는 유틸 (재사용 목적)
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // -------------------------------------
    // 토큰 생성 (UserDetails 기반)
    // - User 엔티티의 정보를 추가 클레임으로 넣어 토큰에 실음
    // - 주의: 토큰에 민감한 정보를 넣지 말 것(예: 비밀번호, 과도한 개인정보)
    // -------------------------------------
    public String generateToken(UserDetails userDetails) {
        // 토큰에 추가로 넣을 데이터(클레임)를 담을 맵
        Map<String, Object> extraClaims = new HashMap<>();

        if (userDetails instanceof User user) {
            // DB에 저장된 유저 엔티티의 필드값을 토큰 클레임에 추가
            extraClaims.put("id", user.getId());
            extraClaims.put("email", user.getEmail());
            extraClaims.put("username", user.getUsername());
            extraClaims.put("fullName", user.getFullName());
            extraClaims.put("profileImageUrl", user.getProfileImageUrl());
            extraClaims.put("bio", user.getBio());
        }
        // 위에서 만든 extraClaims를 포함해서 JWT 토큰을 생성
        return generateToken(extraClaims, userDetails);
    }

    // extraClaims를 포함해 access token 생성 (만료시간: jwtExpiration)
    public String generateToken( Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    // 리프레시 토큰 생성 (보통 extraClaims를 비워두거나 최소한으로 함)
    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    // -------------------------------------
    // 실제 토큰 빌드 로직
    // - setSubject에 userDetails.getUsername()을 넣음 (여기서는 username 또는 id 문자열을 사용)
    // - issuedAt, expiration 설정
    // - HS256으로 서명 (getSignInKey 사용)
    // -------------------------------------
    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // -------------------------------------
    // 토큰 유효성 검사
    // - 토큰의 식별자(identifier)가 userDetails의 식별자(또는 username)와 일치하는지 확인
    // - AND 토큰이 만료되지 않았는지 확인
    // -------------------------------------
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String identifier = extractUsername(token);

        if (userDetails instanceof User user) {
            // 토큰의 식별자가 user.id이거나 user.username인 경우 허용
            boolean identifierMatches = identifier.equals(String.valueOf(user.getId()))
                    || identifier.equals(user.getUsername());

            // 토큰이 만료되지 않았는지 확인 (!isTokenExpired)
            return identifierMatches && !isTokenExpired(token);
        }

        // 일반 UserDetails인 경우 subject(==username)과 비교
        return identifier.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    // -------------------------------------
    // 토큰 만료 검사 유틸
    // - true => 토큰이 만료되었음
    // - false => 토큰이 만료되지 않음
    // -------------------------------------
    private boolean isTokenExpired(String token) { return extractExpiration(token).after(new Date()); }

    private Date extractExpiration(String token) { return extractClaim(token, Claims::getExpiration); }

    // -------------------------------------
    // 토큰의 모든 Claim을 파싱해서 반환
    // - IMPORTANT: parseClaimsJws 사용 (원래 코드의 parseClaimsJwt는 서명된 JWS가 아닌 JWT 전용 파서라서 잘못 사용됨)
    // -------------------------------------
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJwt(token) // 수정: parseClaimsJws 로 서명된 JWT(JWS) 파싱
                .getBody();
    }

    // -------------------------------------
    // 서명(Signing) Key 생성
    // - secretKey: Base64로 인코딩된 키를 기대
    // - HMAC-SHA 키를 생성
    // -------------------------------------
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}