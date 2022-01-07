package com.sion.springsecuritylogin.auth;

import com.sion.springsecuritylogin.model.User;
import com.sion.springsecuritylogin.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Objects;

// security 설정에 따른 요청(loginProcessingUrl("/login"))이 오면
// 자동으로 UserDetailsService 타입으로 IoC 되어있는 loadUserByUsername 함수가 실행된다.
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findOneByUsername(username);

        if (Objects.nonNull(user)) {
            // 이렇게 리턴된 값은 Authentication 내부로 들어가고,
            // Authentication은 security session 내부로 들어가도록 동작된다
            return new PrincipalDetails(user);
        }

        return null;
    }
}
