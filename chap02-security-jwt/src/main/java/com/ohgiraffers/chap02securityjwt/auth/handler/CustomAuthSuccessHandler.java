package com.ohgiraffers.chap02securityjwt.auth.handler;

import ch.qos.logback.core.pattern.ConverterUtil;
import com.ohgiraffers.chap02securityjwt.auth.model.DetailsUser;
import com.ohgiraffers.chap02securityjwt.common.AuthConstants;
import com.ohgiraffers.chap02securityjwt.common.utils.ConvertUtil;
import com.ohgiraffers.chap02securityjwt.common.utils.TokenUtils;
import com.ohgiraffers.chap02securityjwt.user.model.entity.OhUser;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;

public class CustomAuthSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws ServletException, IOException {
        OhUser user = ((DetailsUser) authentication.getPrincipal()).getUser();

        JSONObject jsonValue = (JSONObject) ConvertUtil.convertObjectToJsonObject(user);
        HashMap<String, Object> responseMap = new HashMap<>();

        JSONObject jsonObject;

        if(user.getState().equals("N")){
            responseMap.put("userInfo", jsonValue);
            responseMap.put("message", "탈퇴한 회원입니다.");
        }else{
            String token = TokenUtils.generateJwtToken(user);
            responseMap.put("userInfo", jsonValue);
            responseMap.put("message", "로그인 성공");

            response.addHeader(AuthConstants.AUTH_HEADER, AuthConstants.TOKEN_TYPE + " " + token);
        }

        jsonObject = new JSONObject(responseMap);
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");

        PrintWriter printWriter = response.getWriter();
        printWriter.println(jsonObject);
        printWriter.flush();
        printWriter.close();
    }
}
