package com.hello.springsecurityjwt.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtil {
    private SecretKey secretKey;

    public JWTUtil(@Value("${spring.jwt.secret}") String secret){
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    public String getUsername(String token){
        return Jwts.parser().verifyWith(secretKey) // 토큰이 우리 서버에서 생성되었고, 키가 일치하는지
                .build() // 빌더 타입으로 리턴
                .parseSignedClaims(token) // claim을 확인
                .getPayload().get("username", String.class); // 원하는 정보를 가져온다.
    }

    public String getRole(String token){
        return Jwts.parser().verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload().get("role", String.class);
    }

    public Boolean isExpired(String token){
        return Jwts.parser().verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload().getExpiration().before(new Date()); // 현재 시간을 기준으로 토큰이 만료되었는지 검증
    }

    public String createJwt(String username, String role, Long expiredMs){
        return Jwts.builder()
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                .signWith(secretKey)
                .compact();
    }
}
