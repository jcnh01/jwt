package com.example.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.model.Users;
import com.example.jwt.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;

// JwtAuthorizationFilter는 어떤 요청이 있을 때 작동하는게 아니라
// 스프링 시큐리티는 filter를 가지고 있는데 그 필터중에 BasicAuthenticationFilter라는 것이 있다.
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위의 필터를 무조건 타게 되어있다.
// 권한이나 인증이 필요한 주소가 아니라면 이 필터에 접근하지 않는다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    @Autowired
    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }
    // 인증이나 권한이 필요한 주소 요청이 있을 때 해당 필터를 타게 됨.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 주소 요청이 되었습니다.");
        System.out.println("userRepository: " + userRepository);

        String header = request.getHeader(JwtProperties.HEADER_STRING);

        // 헤더가 없거나 응답한 토큰의 헤더가 아니라면 더 이상 실행안되고 그냥 필터를 타게 함
        if (header == null || !header.startsWith(JwtProperties.TOKEN_PREFIX)) {
            // 헤더가 없거나 응답한 토큰의 헤더가 아니라면 더 이상 실행안되고 그냥 필터를 타게 함
            chain.doFilter(request, response);
            return;
        }

        System.out.println("header : " + header);

        // Authorization이면 BEARER와 공백을 제거하고 토큰만 추출함
        String token = request.getHeader(JwtProperties.HEADER_STRING)
                .replace(JwtProperties.TOKEN_PREFIX, "");

        // 서명이 정상적으로 진행되면 username을 가져와서 string으로 캐스팅해준다.
        String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(token)
                .getClaim("username").asString();

        // 서명이 정상적으로 되었을 때의 조건문
        if (username != null) {
            Users user = userRepository.findByUsername(username);

            // 인증은 토큰 검증시 끝. 인증을 하기 위해서가 아닌 스프링 시큐리티가 수행해주는 권한 처리를 위해
            // 아래와 같이 토큰을 만들어서 Authentication 객체를 강제로 만들고 그걸 세션에 저장
            // 서명이 정상적이니 Authentication 객체를 만들어도 되는 것
            PrincipalDetails principalDetails = new PrincipalDetails(user);
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    principalDetails, // 나중에 컨트롤러에서 DI해서 쓸 때 사용하기 편함.
                    null, // 패스워드는 모르니까 null 처리, 어차피 지금 인증하는게 아니니까
                    principalDetails.getAuthorities());

            // 강제로 시큐리티의 세션에 접근하여 값 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        chain.doFilter(request, response);
    }
}
