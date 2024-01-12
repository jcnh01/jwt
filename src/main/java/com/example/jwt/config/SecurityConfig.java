package com.example.jwt.config;


import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsConfig corsConfig;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(CsrfConfigurer::disable);
        http.sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        // 세션을 사용하지 않는다.

        http.addFilter(corsConfig.corsFilter());
        // 모든 요청이 CorsConfig의 corsFilter를 타서 CORS 요청을 모두 허용

        http.formLogin(formLogin ->
                formLogin.disable()
        );

        http.httpBasic(httpBasic ->
                httpBasic.disable()
        );

        http.authorizeHttpRequests(authorize ->
                authorize
                        .requestMatchers("api/v1/user/**").authenticated()
                        .requestMatchers("api/v1/manager/**").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers("api/v1/admin/**").hasAnyRole("ADMIN")

                        .anyRequest().permitAll()
        );

        return http.build();
    }
}
