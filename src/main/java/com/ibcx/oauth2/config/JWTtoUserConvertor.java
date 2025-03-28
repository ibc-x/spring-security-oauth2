package com.ibcx.oauth2.config;


import java.util.Collections;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import com.ibcx.oauth2.model.User;




@Component
public class JWTtoUserConvertor implements Converter<Jwt, UsernamePasswordAuthenticationToken> {

    @Override
    public UsernamePasswordAuthenticationToken convert(Jwt source) {
        User user = new User();
            user.setLogin(source.getSubject());
            return new UsernamePasswordAuthenticationToken(user, source, Collections.emptyList());
    }
    

}

