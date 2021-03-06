package com.sion.springsecuritylogin.auth;

// 시큐리티가 /login 요청이 오면 낚아채서 로그인을 진행시킨 후,
// 성공하면 시큐리티 Security Session을 만들어준다. (Security ContextHolder)
// Authentication(User정보가 있어야 함) 타입의 객체
// User는 UserDetails 타입의 객체여야 함

import com.sion.springsecuritylogin.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

// Security Session => Authentication => UserDetails
@Data
public class PrincipalDetails  implements UserDetails, OAuth2User {
    private User user; //컴포지션
    private Map<String, Object> attributes;

    // 일반로그인
    public PrincipalDetails(User user) {
        this.user = user;
    }

    // OAuth 로그인
    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    // 해당 User의 권한을 리턴하는 곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });

        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        // 웹사이트에서 1년간 로그인을 안하면 휴먼계정으로 전환하기로 하는 등의 룰이 있을 때
        // 현재시간 - 마지막로그인시간 => 1년을 초과하면 return false 등으로 처리한다

        return true;
    }

    // OAuth2User를 implements하면서 override
    @Override
    public String getName() {
        return null;
    }

    // OAuth2User를 implements하면서 override
    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }
}
