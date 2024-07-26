package com.ohgiraffers.chap02securityjwt.auth.model;

import com.ohgiraffers.chap02securityjwt.user.model.entity.OhUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

public class DetailsUser implements UserDetails {
    private OhUser user;

    public DetailsUser() {
    }

    public DetailsUser(OhUser user) {
        this.user = user;
    }

    public OhUser getUser() {
        return user;
    }

    public void setUser(OhUser user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        user.getRoleList().forEach(role -> authorities.add(() -> role));
        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getUserPass();
    }

    @Override
    public String getUsername() {
        return user.getUserName();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }


    @Override
    public String toString() {
        return "DetailsUser{" +
                "user=" + user +
                '}';
    }
}
