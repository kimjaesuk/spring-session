package com.ohgiraffers.chap02securityjwt.user.repository;

import com.ohgiraffers.chap02securityjwt.user.model.entity.OhUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<OhUser, Integer> {
    Optional<OhUser> findByUserId(String id);

}
