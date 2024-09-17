package com.example.springjwt.config;

import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

// 거의 대부분의 경우 SecurityConfig만으로도 해결되긴 하지만 아래의 경우를 위해 추가함.
// 1. 보안 필터 외부에서의 요청 처리: Spring Security의 CORS 설정은 보안 필터 체인 내에서 처리되는 요청에만 적용됩니다. 그러나 일부 요청이 Spring Security의 보안 필터 체인을 우회하거나 필터 체인 외부에서 직접 처리되는 경우, 보안 설정이 적용되지 않을 수 있습니다. 예를 들어, 요청이 DispatcherServlet에서 직접 처리되는 경우가 이에 해당할 수 있습니다.
// 2. Spring Security의 기본 설정: 기본적으로, Spring Security는 모든 요청을 보호하려고 하지만, Preflight 요청인 OPTIONS 요청은 서버에서 응답을 빠르게 처리하고, 불필요한 인증이나 추가 작업 없이 허용되도록 처리될 수 있습니다.
// 만약 Spring Security 필터 체인에서 OPTIONS 요청에 대한 특정 설정을 하지 않았다면(설정해주면 MVC에서 처리 안해도 되긴함), 보안 필터를 우회하거나 무시하고 처리될 수 있습니다.
public class CorsWebConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry corsRegistry) {

        corsRegistry.addMapping("/**")
                .allowedOrigins("http://localhost:3000");
    }
}
