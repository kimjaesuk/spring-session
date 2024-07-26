package com.ohgiraffers.chap02securityjwt.user.controller;

import com.ohgiraffers.chap02securityjwt.user.model.UserDTO;
import com.ohgiraffers.chap02securityjwt.user.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Objects;

@RestController
public class UserController {

    private UserService userService;
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    public UserController(UserService userService, BCryptPasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }


    @PostMapping("/signup")
    private ResponseEntity signup(@RequestBody UserDTO userDTO){
        UserDTO saveUser = userService.saveUser(userDTO);

        if(Objects.isNull(saveUser)) {
            return ResponseEntity.ok("회원가입 실패");
        }else{
            return ResponseEntity.ok("회원가입 성공");
        }
    }


}
