package com.ohgiraffers.chap02securityjwt.auth.service;

import com.ohgiraffers.chap02securityjwt.auth.model.DetailsUser;
import com.ohgiraffers.chap02securityjwt.user.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class DetailsService implements UserDetailsService {

    private final UserService userService;

    @Autowired
    public DetailsService(UserService userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        if(username == null || username.equals("")){
            throw new AuthenticationServiceException(username + "is empty");
        }else{

            return userService.findUser(username)
                    .map(data -> new DetailsUser(data))
                    .orElseThrow(() -> new AuthenticationServiceException(username));
        }
    }
}
