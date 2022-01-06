package com.sion.springsecuritylogin.controller;

import com.sion.springsecuritylogin.model.User;
import com.sion.springsecuritylogin.repository.UserRepository;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
public class IndexController {
    private final UserRepository userRepository;

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/join")
    public String join() {
        return "join";
    }

    @PostMapping("/join")
    @ResponseBody
    public String join(User user) {
        System.out.println("successfully joined! " + user.getUsername());

        user.setRole("ROLE_USER");
        userRepository.save(user); // TODO 이 상태로는 비밀번호가 암호화가 되어있지 않아서 시큐리티로 로그인 할 수 없다.

        return "join";
    }
}
