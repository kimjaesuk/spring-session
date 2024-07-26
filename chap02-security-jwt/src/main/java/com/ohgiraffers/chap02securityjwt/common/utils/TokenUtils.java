package com.ohgiraffers.chap02securityjwt.common.utils;

import com.ohgiraffers.chap02securityjwt.user.model.entity.OhUser;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class TokenUtils {

    private static String jwtSecretKey;
    private static Long tokenValidateTime;

    @Value("${jwt.key}")
    public void setJwtSecretKey(String jwtSecretKey) {
        TokenUtils.jwtSecretKey = jwtSecretKey;
    }

    @Value("${jwt.time}")
    public void setTokenValidateTime(Long tokenValidateTime) {
        TokenUtils.tokenValidateTime = tokenValidateTime;
    }

    /**
     * header의 token을 분리하는 메서드
     * @param header : Authrization의 header 값을 가져온다.
     * @return token : Authrization의 token 부분을 반환한다.
     */
    public static String splitHeader(String header){
        if(!header.equals("")){
            return header.split(" ")[1];
        }else{
            return null;
        }
    }

    /**
     * 유효한 토큰인지 확인하는 메서드
     *
     * @param token : 토큰
     * @return boolean : 유효 여부
     * @throws io.jsonwebtoken.ExpiredJwtException,
     * */
    public static boolean isValidToken(String token){
        try{
            Claims claims = getClaimsFormToken(token);
            return true;
        }catch (ExpiredJwtException e){
            e.printStackTrace();
            return false;
        }catch (JwtException e){
            e.printStackTrace();
            return false;
        }catch (NullPointerException e){
            e.printStackTrace();
            return false;
        }
    }

    /**
     * 토큰을 복호화 하는 메서드
     * @param token
     * @return Claims
     * */
    public static Claims getClaimsFormToken(String token){
        return Jwts.parser()
                .setSigningKey(DatatypeConverter.parseBase64Binary(jwtSecretKey))
                .parseClaimsJws(token).getBody();
    }

    /**
     * token을 생성하는 메서드
     * @param user - userEntity
     * @return String token
     * */
    public static String generateJwtToken(OhUser user){
        Date expireTime = new Date(System.currentTimeMillis() + tokenValidateTime);

        JwtBuilder builder = Jwts.builder()
                .setHeader(createHeader())
                .setClaims(createClaims(user))
                .setSubject("ohgiraffers token : " + user.getUserNo())
                .signWith(SignatureAlgorithm.HS256, createSignature())
                .setExpiration(expireTime);
        return builder.compact();
    }



    /**
     * token의 header를 설정하는 함수
     * @return Map<String, Object> header의 설정 정보
     * */
    private static Map<String, Object> createHeader(){
        Map<String, Object> header = new HashMap<>();

        header.put("type", "jwt");
        header.put("alg", "HS256");
        header.put("data", System.currentTimeMillis());
        return header;
    }

    private static Map<String, Object> createClaims(OhUser user) {
        Map<String, Object> claims = new HashMap<>();

        claims.put("userName", user.getUserName());
        claims.put("Role", user.getRole());
        claims.put("userEmail", user.getUserEmail());

        return claims;
    }


    private static Key createSignature(){
        byte[] secretBytes = DatatypeConverter.parseBase64Binary(jwtSecretKey);
        return new SecretKeySpec(secretBytes, SignatureAlgorithm.HS256.getJcaName());
    }

}
