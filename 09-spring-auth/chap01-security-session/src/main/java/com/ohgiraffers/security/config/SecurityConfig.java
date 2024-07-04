package com.ohgiraffers.security.config;

import com.ohgiraffers.security.config.handler.AuthFailHandler;
import com.ohgiraffers.security.user.model.dto.UserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AuthFailHandler failHandler;
    @Autowired
    public SecurityConfig(AuthFailHandler failHandler) {
        this.failHandler = failHandler;
    }

    /*
     * 비밀번호를 인코딩 하기 위한 bean
     * Bcrypt는 비밀번호 해싱에 가장 많이 사용되는 알고리즘 중 하나이다.
     * */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth ->{
            auth.requestMatchers("/auth/login","user/signup","/auth/fail","/").permitAll();
            auth.requestMatchers("/admin/*").hasAnyAuthority(UserRole.ADMIN.getRole());
            auth.requestMatchers("/user/*").hasAnyAuthority(UserRole.USER.getRole());
            auth.anyRequest().authenticated();
        }).formLogin(login -> {
            login.loginPage("/auth/login");
            login.usernameParameter("user");
            login.passwordParameter("pass");
            login.defaultSuccessUrl("/");
            login.failureHandler(failHandler);
        }).logout(logout ->{
            logout.logoutRequestMatcher(new AntPathRequestMatcher("/auth/logout"));
            logout.deleteCookies("JSESSIONID");
            logout.invalidateHttpSession(true);
            logout.logoutSuccessUrl("/");
        }).sessionManagement(session ->{
            session.maximumSessions(1); // 중복로그인설정 1개만 하겠다.
            session.invalidSessionUrl("/");
        }).csrf(csrf -> csrf.disable());
        return http.build();
    }
}
