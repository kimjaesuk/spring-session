package com.ohgiraffers.security.auth.service;

import com.ohgiraffers.security.auth.model.AuthDetails;
import com.ohgiraffers.security.user.model.entity.User;
import com.ohgiraffers.security.user.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service // 이 클래스가 서비스 역할을 한다고 Spring에게 알려줍니다.
public class AuthService implements UserDetailsService {

    private final UserService userService; // 유저 정보를 관리하는 서비스입니다.

    @Autowired // 자동으로 필요한 의존성을 주입받습니다.
    public AuthService(UserService userService) {
        this.userService = userService; // 생성자로 유저 서비스를 받아옵니다.
    }

    @Override // UserDetailsService 인터페이스의 메소드를 구현합니다.
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userService.findByUserId(username); // 유저 아이디로 유저 정보를 찾습니다.

        if(Objects.isNull(user)){
            throw new UsernameNotFoundException("회원정보가 존재하지 않습니다."); // 유저 정보가 없으면 예외를 던집니다.
        }

        return new AuthDetails(user); // 유저 정보가 있으면 AuthDetails 객체를 반환합니다.
    }

}
