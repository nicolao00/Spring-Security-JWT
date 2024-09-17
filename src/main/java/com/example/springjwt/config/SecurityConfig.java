package com.example.springjwt.config;

import com.example.springjwt.jwt.JWTFilter;
import com.example.springjwt.jwt.JWTUtil;
import com.example.springjwt.jwt.LoginFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
    }
    //AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    // 스프링 시큐리티는 항상 비밀번호를 암호화해서 저장하는데 그렇게 사용할 수 있도록 메소드를 빈으로 등록!
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors((corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {

                    // CorsConfigurationSource 인터페이스의 메서드로, 주어진 요청에 대한 CORS 설정을 반환한다.
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {


                        CorsConfiguration configuration = new CorsConfiguration();

                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                        configuration.setAllowedMethods(Collections.singletonList("*"));
                        // 자격 증명(쿠키, 인증 정보 등)의 사용을 허용할지 여부를 설정. true로 설정하면 클라이언트에서 인증된 요청을 보낼 수 있습니다.
                        configuration.setAllowCredentials(true);
                        // 허용할 HTTP 헤더를 설정합니다. "*"로 설정함으로써 모든 헤더를 허용합니다. (여기서는 Authorization 헤더 사용!!!)
                        configuration.setAllowedHeaders(Collections.singletonList("*"));
                        configuration.setMaxAge(3600L);

                        // 백엔드에서 클라이언트 쪽으로 Authorization 헤더에 JWT를 넣어서 보내줄 것이라 Authorization 헤더 추가
                        configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                        return configuration;
                    }
                })));

        //csrf disable
        http
                .csrf((auth) -> auth.disable());

        //Form 로그인 방식 disable
        http
                .formLogin((auth) -> auth.disable());

        //http basic 인증 방식 disable
        http
                .httpBasic((auth) -> auth.disable());

        //경로별 인가 작업
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated());

        //JWTFilter 등록 (로그인 필터 작동 전에 동작하도록 위치 설정)
        http
                .addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);

        //필터 추가 LoginFilter()는 인자를 받음 (AuthenticationManager() 메소드에 authenticationConfiguration 객체를 넣어야 함) 따라서 빈 등록 필요
        // 기존 시큐리티 필터에 있는 UsernamePasswordAuthenticationFilter에 우리가 작성한 새로운 필터를 덮어 씌울거라 addFilterAt을 사용했음.
        http
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);

        //세션 설정 (가장 중요!!!!!!!!!!)
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }
}
