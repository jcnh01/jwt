package com.example.jwt.controller;

import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.model.Users;
import com.example.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("api/v1")
@RequiredArgsConstructor
public class RestApiController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/home")
    public String home() {
        return "home";
    }

    @PostMapping("/token")
    public String token() {
        return "token";
    }

    @PostMapping("/join")
    public String join(@RequestBody Users user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "회원가입완료";
    }

    @GetMapping("/user")
    public String user(Authentication authentication) {
        PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("principal의 id : " + principal.getUser().getId());
        System.out.println("principal의 username : " + principal.getUser().getUsername());
        System.out.println("principal의 password : " + principal.getUser().getPassword());

        return "user";
    }

    // 매니저 혹은 어드민이 접근 가능
    @GetMapping("manager/reports")
    public String reports() {
        return "reports";
    }

    // 어드민이 접근 가능
    @GetMapping("admin/users")
    public List<Users> users() {
        return userRepository.findAll();
    }
}
