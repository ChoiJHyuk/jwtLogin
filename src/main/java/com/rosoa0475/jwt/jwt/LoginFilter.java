package com.rosoa0475.jwt.jwt;

import com.rosoa0475.jwt.dto.CustomUserDetails;
import com.rosoa0475.jwt.entity.RefreshEntity;
import com.rosoa0475.jwt.repository.RefreshRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final JWTUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final RefreshRepository refreshRepository;
    //security config에서 인자로 넘어오므로 @RequiredArgsConstructor 사용 X
    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil, RefreshRepository refreshRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.refreshRepository = refreshRepository;
    }

    @Override
    //공부자료 05에 있는 Authentication 생성하는 함수
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        //클라이언트 요청에서 username, password 추출해주는 함수
        String username = obtainUsername(request);
        String password = obtainPassword(request);
        System.out.println(username);

        //AuthenticationManager에서 검증을 하려면 token에 담아야 함, SecurityContextHolder에 저장되어야 하는 객체
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password, null);
        //token을 AuthenticationManager에게 전달
        //반환값엔 token에 대한 정보와 UserDetail을 구현한 클래스의 정보가 들어있다.
        return authenticationManager.authenticate(authRequest);
    }

    //로그인 실패시 실행되는 메서드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setStatus(401);
    }

    //로그인 성공시 실행되는 메서드 여기서 jwt 발급하면 됨
    @Override                                                                                                           //UsernamePasswordAuthenticationFilter가 반환한 객체
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        
        //단일 토큰 방식                                                    //UserDetail 반환하는 함수
        /*CustomUserDetails customUserDetails = (CustomUserDetails) authResult.getPrincipal();
        String username = authResult.getName();
                                                        //UserDetail을 구현한 클래스의 함수 호출
        Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority grantedAuthority = iterator.next();

        String role = grantedAuthority.getAuthority();
        String token = jwtUtil.createToken(username, role, 60*60*10L);
        response.addHeader("Authorization", "Bearer " + token);*/
        
        //다중 토큰 방식
        String username = authResult.getName();

        Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority grantedAuthority = iterator.next();
        String role = grantedAuthority.getAuthority();

        String access = jwtUtil.createJwt("access", username, role, 600000L);
        String refresh = jwtUtil.createJwt("refresh", username, role, 86400000L);

        addRefreshEntity(username,refresh,8640000L);

        //같은 이름으로 된 헤더가 있으면 그 헤더를 바꿔주는 함수, but 존재하지 않으면 addHeader() 함수랑 같음
        response.setHeader("access", access);
        response.addCookie(createCookie("refresh", refresh));
        response.setStatus(HttpStatus.OK.value());
    }

    private void addRefreshEntity(String username, String refresh, Long expiredMs) {

        Date date = new Date(System.currentTimeMillis() + expiredMs);

        RefreshEntity refreshEntity = new RefreshEntity();
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());

        refreshRepository.save(refreshEntity);
    }

    private Cookie createCookie(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        //쿠키의 생명주기 설정
        cookie.setMaxAge(24*60*60);
        //https로 통신할 경우 이 값을 넣어줌
        //cookie.setSecure(true);
        //쿠키가 적용될 범위 설정
        //cookie.setPath("/");
        //자바스크립트로 이 쿠키에 접근하지 못하도록 설정
        cookie.setHttpOnly(true);

        return cookie;
    }
}
