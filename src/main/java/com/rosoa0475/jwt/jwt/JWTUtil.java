package com.rosoa0475.jwt.jwt;

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
        //properties에 있는 jwt secret 키를 HS256알고리즘으로 암호화
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    public String getUserName(String token){
        //verifyWith()함수로 token이 이 서버에서 만들었는지 확인
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username",String.class);
    }

    public String getRole(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public Boolean isExpired(String token) {

                                                                                //현재 시간 기준으로 before이면 true 반환
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    public String createToken(String username, String role, Long expiredMs){
                //jwt token 만들어서 반환
        return Jwts.builder()
                .claim("username", username) // Payload에 값 저장하는 함수
                .claim("role",role)
                .issuedAt(new Date(System.currentTimeMillis())) // 토큰이 만들어진 시간
                .expiration(new Date(System.currentTimeMillis()+expiredMs)) // 토큰이 만료되는 시간
                .signWith(secretKey) // secretKey 이용해 signature 생성
                .compact();
    }
}
