package com.ohgiraffers.chap02securityjwt.auth.filter;

import com.ohgiraffers.chap02securityjwt.auth.model.DetailsUser;
import com.ohgiraffers.chap02securityjwt.common.AuthConstants;
import com.ohgiraffers.chap02securityjwt.common.utils.TokenUtils;
import com.ohgiraffers.chap02securityjwt.user.model.entity.OhUser;
import com.ohgiraffers.chap02securityjwt.user.model.entity.OhgiraffersRole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        //권한이 필요없는 요청
        List<String> roleLessList = Arrays.asList(
                "/signup"
        );

        if(roleLessList.contains(request.getRequestURI())){
            chain.doFilter(request,response);
            return;
        }
        String header = request.getHeader(AuthConstants.AUTH_HEADER);

        try {
            if(header != null && !header.equalsIgnoreCase("")){
                String token = TokenUtils.splitHeader(header);

                if(TokenUtils.isValidToken(token)){
                    Claims claims = TokenUtils.getClaimsFormToken(token);
                    System.out.println(OhgiraffersRole.valueOf(claims.get("Role").toString()));
                    DetailsUser authentication  = new DetailsUser();
                    OhUser user = new OhUser();
                    user.setUserId(claims.get("userName").toString());
                    user.setRole(OhgiraffersRole.valueOf(claims.get("Role").toString()));
                    authentication.setUser(user);


                    AbstractAuthenticationToken authenticationToken = UsernamePasswordAuthenticationToken.authenticated(authentication, token, authentication.getAuthorities());
                    authenticationToken.setDetails(new WebAuthenticationDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    chain.doFilter(request,response);
                }else {
                    throw new RuntimeException("토큰이 유효하지 않습니다.");
                }
            }else{

                throw new RuntimeException("토큰이 존재하지 않습니다.");
            }
        }catch (Exception e){
            response.setCharacterEncoding("UTF-8");
            response.setContentType("application/json");
            PrintWriter printWriter = response.getWriter();
            JSONObject jsonObject = jsonreponseWrapper(e);
            printWriter.println(jsonObject);
            printWriter.flush();
            printWriter.close();
        }
    }

    private JSONObject jsonreponseWrapper(Exception e) {
        e.printStackTrace();
        String resultMsg = "";
        if(e instanceof ExpiredJwtException){
            resultMsg = "TOKEN EXPIRED";
        } else if (e instanceof SignatureException) {
            resultMsg = "Token Parsing JwtException";
        }else{
            resultMsg = "Other Token Error";
        }
        HashMap<String, Object> jsonMap = new HashMap<>();
        jsonMap.put("status", 401);
        jsonMap.put("message", resultMsg);
        jsonMap.put("reason", e.getMessage());
        JSONObject jsonObject = new JSONObject(jsonMap);
        return jsonObject;

    }
}
