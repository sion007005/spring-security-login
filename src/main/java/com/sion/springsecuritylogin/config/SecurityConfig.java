package com.sion.springsecuritylogin.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록된다.
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured 어노테이션을 활성화 시킨다. + 뒤에꺼는 preAuthorize 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                .antMatchers("/user/**").authenticated()
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin() // 권한이 없는 사람이 접근하면 로그인 페이지로 이동시킨다
                .loginPage("/login")
//                .usernameParameter("name") form 에서 넘기는 name="username"을 "name"으로 하고 싶다면 이렇게 설정한다. (DetailsService의 loadUserByUsername 함수의 파라미터이름과 매칭)
                .loginProcessingUrl("/login") // login이 호출되면, 컨트롤러에서 매핑시키지 않아도 시큐리티가 낚아채서 대신 로그인 실행한다.
                .defaultSuccessUrl("/");
    }

    @Bean
    public BCryptPasswordEncoder encodePassword() {
        return new BCryptPasswordEncoder();
    }
}
