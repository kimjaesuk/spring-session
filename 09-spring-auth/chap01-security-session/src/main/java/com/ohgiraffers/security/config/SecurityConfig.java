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
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration // 설정 파일이라는 것을 나타냅니다.
@EnableWebSecurity // 웹 보안을 활성화합니다.
public class SecurityConfig {

    private final AuthFailHandler failHandler; // 로그인 실패 시 처리하는 핸들러입니다.

    @Autowired // 자동으로 필요한 의존성을 주입받습니다.
    public SecurityConfig(AuthFailHandler failHandler) {
        this.failHandler = failHandler; // 생성자로 핸들러를 받아옵니다.
    }

    @Bean // Spring에서 객체를 관리하기 위해 Bean으로 등록합니다.
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(); // 비밀번호를 암호화하는 도구를 사용합니다.
    }

    @Bean // Spring에서 객체를 관리하기 위해 Bean으로 등록합니다.
    public WebSecurityCustomizer webSecurityCustomizer(){
        return web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
        // 정적인 파일들(CSS, JS 등)은 보안 설정을 무시합니다.
    }

    @Bean // Spring에서 객체를 관리하기 위해 Bean으로 등록합니다.
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth ->{
            auth.requestMatchers("/auth/login","user/signup","/auth/fail","/").permitAll();
            // 로그인, 회원가입, 실패 페이지는 누구나 접근할 수 있습니다.
            auth.requestMatchers("/admin/*").hasAnyAuthority(UserRole.ADMIN.getRole());
            // 관리자 페이지는 관리자만 접근할 수 있습니다.
            auth.requestMatchers("/user/*").hasAnyAuthority(UserRole.USER.getRole());
            // 사용자 페이지는 사용자만 접근할 수 있습니다.
            auth.anyRequest().authenticated();
            // 그 외의 페이지는 인증된 사용자만 접근할 수 있습니다.
        }).formLogin(login -> {
            login.loginPage("/auth/login");
            // 로그인 페이지 경로를 설정합니다.
            login.usernameParameter("user");
            // 로그인 시 사용할 사용자명 파라미터 이름을 설정합니다.
            login.passwordParameter("pass");
            // 로그인 시 사용할 비밀번호 파라미터 이름을 설정합니다.
            login.defaultSuccessUrl("/");
            // 로그인 성공 시 이동할 경로를 설정합니다.
            login.failureHandler(failHandler);
            // 로그인 실패 시 사용할 핸들러를 설정합니다.
        }).logout(logout ->{
            logout.logoutRequestMatcher(new AntPathRequestMatcher("/auth/logout"));
            // 로그아웃 경로를 설정합니다.
            logout.deleteCookies("JSESSIONID");
            // 로그아웃 시 쿠키를 삭제합니다.
            logout.invalidateHttpSession(true);
            // 로그아웃 시 세션을 무효화합니다.
            logout.logoutSuccessUrl("/");
            // 로그아웃 성공 시 이동할 경로를 설정합니다.
        }).sessionManagement(session ->{
            session.maximumSessions(1); // 중복 로그인 시 최대 세션 수를 1개로 제한합니다.
            session.invalidSessionUrl("/");
            // 세션이 유효하지 않을 때 이동할 경로를 설정합니다.
        }).csrf(csrf -> csrf.disable());
        // CSRF 보안을 비활성화합니다.
        return http.build();
    }
}
