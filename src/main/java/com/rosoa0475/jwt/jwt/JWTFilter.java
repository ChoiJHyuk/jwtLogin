package com.rosoa0475.jwt.jwt;

import com.rosoa0475.jwt.dto.CustomUserDetails;
import com.rosoa0475.jwt.entity.UserEntity;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;

public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //단일 토큰 방식
        /*String authorization = request.getHeader("Authorization");
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            System.out.println("token null");
            // 다음 필터로 넘김
            filterChain.doFilter(request, response);
            return;
        }

        String token = authorization.substring("Bearer ".length());
        if(jwtUtil.isExpired(token)){
            System.out.println("token expired");
            filterChain.doFilter(request, response);
            return;
        }
        String username = jwtUtil.getUserName(token);
        String role = jwtUtil.getRole(token);

        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setRole(role);
        //비번은 안 필요함

        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        //이미 로그인 되어있는 상태이므로 LoginFilter 안 거침 따라서 attemptAuthentication() 대신하여 Authentication 생성
        //Authentication 객체를 통해 권한 확인 / 이는 세션의 한 종류이지만 응답이 완료되면 바로 삭제됨
        Authentication authentication = new UsernamePasswordAuthenticationToken(customUserDetails,null, customUserDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);*/

        //다중 토큰 방식
        String accessToken = request.getHeader("access");

        if(accessToken == null) {
            filterChain.doFilter(request, response);
            return;
        }
        //단일 토큰 방식은 엄밀히 잘못된 방식, try-catch문으로 감쏴줘야 한다.
        try{
            jwtUtil.isExpired(accessToken);
        }catch(ExpiredJwtException e){
            PrintWriter writer = response.getWriter();
            writer.print("access token expired");

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        String category = jwtUtil.getCategory(accessToken);
        if(!category.equals("access")) {
            PrintWriter writer = response.getWriter();
            writer.print("invalid access token");

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        String username = jwtUtil.getUserName(accessToken);
        String role = jwtUtil.getRole(accessToken);
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setRole(role);
        CustomUserDetails userDetails = new CustomUserDetails(userEntity);
        Authentication auth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(auth);
        filterChain.doFilter(request, response);
    }
}
