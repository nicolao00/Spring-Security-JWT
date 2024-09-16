package com.example.springjwt.jwt;

import com.example.springjwt.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    // 얘가 이제 DB에서 가져온 유저 정보과 본 클래스에서 넘겨준 Token으로 검증을 진행함
    private final AuthenticationManager authenticationManager;

    private final JWTUtil jwtUtil;

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        //클라이언트 요청에서 username, password 추출
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        System.out.println(username);

        //스프링 시큐리티에서 username과 password를 검증하기 위해서는 token에 담아야 함
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        //token에 담은 검증을 위한 AuthenticationManager로 전달
        return authenticationManager.authenticate(authToken);
    }

    //로그인 성공시 실행하는 메소드 (여기서 JWT를 발급하면 됨)
    /*
    Authentication 객체는 스프링 시큐리티(Spring Security)에서 인증된 사용자 정보를 담고 있는 객체입니다. 이 객체에는 사용자의 아이디(username), 권한(authorities), 그리고 사용자에 대한 추가적인 정보들이 포함되어 있습니다.
        - getPrincipal(): 인증된 사용자의 주요 정보를 가져옵니다. 일반적으로 사용자 객체나 사용자 ID를 반환합니다. CustomUserDetails 객체로 캐스팅하여 추가적인 사용자 정보를 사용할 수 있습니다.
        - getAuthorities(): 사용자가 가지고 있는 권한 목록(Authorities)을 반환합니다. 권한은 주로 역할(Role)이나 권한 수준을 나타내며, JWT 토큰에 포함하여 클라이언트와 서버 간의 권한 검증에 사용됩니다.
    */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {
        // 유저 객체를 알아보기 위함. UserDetail
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

        String username = customUserDetails.getUsername();

        //  (iterator.next() 사용 이유)
        // authentication.getAuthorities()는 사용자의 권한(Authorities)을 Collection 형태로 반환합니다. 이는 사용자가 여러 권한을 가질 수 있기 때문입니다.
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        // GrantedAuthority는 각 권한을 나타내는 인터페이스입니다.
        GrantedAuthority auth = iterator.next();

        String role = auth.getAuthority();

        String token = jwtUtil.createJwt(username, role, 60*60*10L);

        // HTTP 인증 방식은 RFC 7235 정의에 따라 아래 인증 헤더 형태를 가져야하기 때문에 양식에 맞춰 작성한 것.Authorization: 타입 인증토큰
        //예시
        //Authorization: Bearer 인증토큰string
        // 이 값은 postman Response -> Headers -> Authoriztation 칸에서 확인 가능하다. Bearer [Token 값~(header, payload, Signature)]
        // 그럼 이제 그 값을 요청 header에 넣어서 인증 가능!!!!
        response.addHeader("Authorization", "Bearer " + token);

    }

    //로그인 실패시 실행하는 메소드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        response.setStatus(401);
    }
}
