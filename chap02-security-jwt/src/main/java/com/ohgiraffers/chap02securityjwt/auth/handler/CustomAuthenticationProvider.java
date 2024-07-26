package com.ohgiraffers.chap02securityjwt.auth.handler;

import com.ohgiraffers.chap02securityjwt.auth.model.DetailsUser;
import com.ohgiraffers.chap02securityjwt.auth.service.DetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Objects;

public class CustomAuthenticationProvider implements AuthenticationProvider {
    @Autowired
    private DetailsService detailsService;
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;


    public CustomAuthenticationProvider() {

    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UsernamePasswordAuthenticationToken loginToken = (UsernamePasswordAuthenticationToken) authentication;

        String id = loginToken.getName();
        String pass = (String) loginToken.getCredentials();
        DetailsUser detailsUser = (DetailsUser) detailsService.loadUserByUsername(id);

        if(!passwordEncoder.matches(pass, detailsUser.getPassword())){
            throw new BadCredentialsException("비밀번호가 달라유~");
        }
        return new UsernamePasswordAuthenticationToken(detailsUser, pass, detailsUser.getAuthorities());
     }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
