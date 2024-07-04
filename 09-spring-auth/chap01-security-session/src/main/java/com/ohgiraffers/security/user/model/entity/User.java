package com.ohgiraffers.security.user.model.entity;

import com.ohgiraffers.security.user.model.dto.UserRole;
import jakarta.persistence.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Entity
@Table(name = "TBL_USER")
public class User {

    @Id
    @Column(name = "user_no")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int userNo;
    @Column(name = "user_id")
    private String userId;
    @Column(name = "user_name")
    private String userName;
    @Column(name = "password")
    private String password;
    @Column(name = "user_role")
    @Enumerated(EnumType.STRING)
    private UserRole userRole;

    public List<String> getRoleList(){
        if(this.userRole.getRole().length()>0){
            return Arrays.asList(this.userRole.getRole().split(","));
        }
        return new ArrayList<>();
    }

    public User() {
    }

    public User(int userNo, String userId, String userName, String password, UserRole userRole) {
        this.userNo = userNo;
        this.userId = userId;
        this.userName = userName;
        this.password = password;
        this.userRole = userRole;
    }

    public int getUserNo() {
        return userNo;
    }

    public void setUserNo(int userNo) {
        this.userNo = userNo;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public UserRole getUserRole() {
        return userRole;
    }

    public void setUserRole(UserRole userRole) {
        this.userRole = userRole;
    }

    @Override
    public String toString() {
        return "User{" +
                "userNo=" + userNo +
                ", userId='" + userId + '\'' +
                ", userName='" + userName + '\'' +
                ", password='" + password + '\'' +
                ", userRole=" + userRole +
                '}';
    }
}