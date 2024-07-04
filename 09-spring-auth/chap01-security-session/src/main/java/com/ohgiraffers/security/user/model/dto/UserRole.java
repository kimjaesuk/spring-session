package com.ohgiraffers.security.user.model.dto;

public enum UserRole {
    USER("USER"),
    ADMIN("ADMIN"),
    ALL("USER,ADMIN");
    private String role;

    UserRole(String role) {
        this.role = role;
    }

    public String getRole() {
        return role;
    }

    @Override
    public String toString() {
        return "UserRole{" +
                "role='" + role + '\'' +
                '}';
    }
}