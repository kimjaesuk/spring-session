package com.ohgiraffers.chap02securityjwt.user.service;

import com.ohgiraffers.chap02securityjwt.user.model.UserDTO;
import com.ohgiraffers.chap02securityjwt.user.model.entity.OhUser;
import com.ohgiraffers.chap02securityjwt.user.model.entity.OhgiraffersRole;
import com.ohgiraffers.chap02securityjwt.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    private UserRepository userRepository;
    private BCryptPasswordEncoder encoder;

    @Autowired
    public UserService(UserRepository userRepository, BCryptPasswordEncoder encoder) {
        this.userRepository = userRepository;
        this.encoder = encoder;
    }


    public UserDTO saveUser(UserDTO saveUserDTO){
        // 비즈니스 로직 추가
        OhUser ohUser = new OhUser();
        ohUser.setUserName(saveUserDTO.getUserName());
        ohUser.setUserId(saveUserDTO.getUserId());

        ohUser.setUserPass(encoder.encode(saveUserDTO.getUserPass()));
        ohUser.setRole(OhgiraffersRole.valueOf(saveUserDTO.getRole()));
        ohUser.setState("Y");

        OhUser saveUser = userRepository.save(ohUser);

        // 등록 완료 로직 추가
        saveUserDTO.setUserId(saveUser.getUserId());
        saveUserDTO.setUserPass(saveUser.getUserPass());
        saveUserDTO.setUserName(saveUser.getUserName());

        return saveUserDTO;

    }

    public Optional<OhUser> findUser(String id){
        Optional<OhUser> user = userRepository.findByUserId(id);

        return user;
    }
}
