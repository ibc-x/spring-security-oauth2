package com.ic.ioauth2.config;


import java.util.Collections;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import com.ic.ioauth2.model.CustomUser;




@Component
public class JWTtoUserConvertor implements Converter<Jwt, UsernamePasswordAuthenticationToken> {

    @Override
    public UsernamePasswordAuthenticationToken convert(Jwt source) {
        CustomUser user = new CustomUser();
            user.setLogin(source.getSubject());
            //user.setId(source.getSubject());
            return new UsernamePasswordAuthenticationToken(user, source, Collections.emptyList());
    }
    

}

