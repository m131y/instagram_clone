package com.my131.backend.security;

import com.my131.backend.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    // application.yml, 환경변수로부터 주입
    @Value("${JWT_SECRET}")
    private String secretKey;

    @Value("${JWT_EXPIRATION}")
    private long jwtExpiration;

    @Value("${JWT_REFRESH_EXPIRATION}")
    private long refreshExpiration;

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
        Map<String, Object> extraClaims = new HashMap<>();

        if (userDetails instanceof User user) {
            extraClaims.put("id", user.getId());
            extraClaims.put("email", user.getEmail());
            extraClaims.put("username", user.getUsername());
            extraClaims.put("fullName", user.getFullName());
            extraClaims.put("profileImageUrl", user.getProfileImageUrl());
            extraClaims.put("bio", user.getBio());
        }

        return generateToken(extraClaims, userDetails);
    }

    public String generateToken( Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    // claims 와 userDetails, expiration 을 사용해 토큰 생성
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

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String identifier = extractUsername(token);

        if (userDetails instanceof User user) {
            boolean isValid = identifier.equals(String.valueOf(user.getId()))
                    || identifier.equals(user.getUsername());

            return isValid && isTokenExpired(token);
        }

        return (identifier.equals(userDetails.getUsername())) && isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) { return extractExpiration(token).after(new Date()); }

    private Date extractExpiration(String token) { return extractClaim(token, Claims::getExpiration); }

    // 토큰에서 모든 claim 을 추출
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJwt(token)
                .getBody();
    }

    // secretKey 를 이용해 signKey 를 생성
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}