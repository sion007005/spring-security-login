package com.sion.springsecuritylogin.oauth;

import com.sion.springsecuritylogin.auth.PrincipalDetails;
import com.sion.springsecuritylogin.model.User;
import com.sion.springsecuritylogin.oauth.provider.FacebookUserInfo;
import com.sion.springsecuritylogin.oauth.provider.GoogleUserInfo;
import com.sion.springsecuritylogin.oauth.provider.OAuth2UserInfo;
import com.sion.springsecuritylogin.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {
//    private final BCryptPasswordEncoder bCryptPasswordEncoder; 순환참조 에러로 주석처리
    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        System.out.println("userRequest.getClientRegistration() = " + userRequest.getClientRegistration());

        OAuth2User oauth2User = super.loadUser(userRequest);
        System.out.println("getAttributes: " + oauth2User.getAttributes()); // 필요한 정보는 여기에 있다. (사용자이름, 이메일 등)

        // 자동으로 회원가입 시킨다.
        OAuth2UserInfo oauth2UserInfo = null;
        String provider = userRequest.getClientRegistration().getRegistrationId();
        if (provider.equals("google")) {
            oauth2UserInfo = new GoogleUserInfo(oauth2User.getAttributes());
        } else if (provider.equals("facebook")) {
            oauth2UserInfo = new FacebookUserInfo(oauth2User.getAttributes());
        } else {
            System.out.println(provider + " 로그인은 지원하지 않습니다.");
        }

        String providerId = oauth2UserInfo.getProviderId();
        String username = provider + "_" + providerId;
        String email = oauth2UserInfo.getEmail();
//        String password = bCryptPasswordEncoder.encode("getinthere"); // 비밀번호는 크게 의미없음
        String role = "ROLE_USER";

        // 가입된 회원인지 확인한다.
        User userEntity = userRepository.findOneByUsername(username);

        if (Objects.isNull(userEntity)) {
            userEntity = User.builder()
                            .username(username)
//                            .password("temp")
                            .email(email)
                            .role(role)
                            .provider(provider)
                            .providerId(providerId)
                            .build();

            userRepository.save(userEntity);
        }

        return new PrincipalDetails(userEntity, oauth2User.getAttributes()); // 만들어진 객체는 Authentication에 들어간다.
    }
}
