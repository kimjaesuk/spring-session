package com.ohgiraffers.security.user.service;

import com.ohgiraffers.security.user.dao.UserRepository;
import com.ohgiraffers.security.user.model.dto.SignupDTO;
import com.ohgiraffers.security.user.model.dto.UserRole;
import com.ohgiraffers.security.user.model.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;

@Service
public class UserService {

    private final PasswordEncoder encoder;
    private final UserRepository userRepository;

    @Autowired
    public UserService(PasswordEncoder encoder, UserRepository userRepository) {
        this.encoder = encoder;
        this.userRepository = userRepository;
    }

    @Transactional
    public Integer regist(SignupDTO signupDTO) {
        User user = userRepository.findByuserId(signupDTO.getUserId());

        if (!Objects.isNull(user)) {
            return null;
        }

        user = new User();
        user.setUserId(signupDTO.getUserId());
        user.setUserName(signupDTO.getUserName());
        user.setUserRole(UserRole.valueOf(signupDTO.getRole()));
        user.setPassword(encoder.encode(signupDTO.getUserPass()));

        User saveUser = userRepository.save(user);

        if (Objects.isNull(saveUser)) {
            return 0;
        } else {
            return 1;
        }
    }

    public User findByUserID(String username) {
        return null;
    }

    public User findByUserId(String username) {

        User user = userRepository.findByuserId(username);

        if (Objects.isNull(user)) {
            return null;
        }
        return user;
    }
}
