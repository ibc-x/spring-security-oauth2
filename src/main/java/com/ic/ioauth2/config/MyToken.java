package com.ic.ioauth2.config;

import java.time.Instant;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

@Service
public class MyToken {

    @Autowired
	private JwtEncoder jwtEncoder;

    /**
     * @param subject entity / utilisateur
     * @param claim  les authorisations de l'utilisateur
     * @param issuedAt Date et heure de création du token
     * @param expiresAt  Date et heure d'expiration du token
     * @return String
     */
    public String generate(String subject, String claim, Instant issuedAt, Instant expiresAt){

            JwtClaimsSet jwtClaimsSet=JwtClaimsSet.builder()
			.issuedAt(issuedAt)
			.expiresAt(expiresAt)
			.subject(subject)
			.claim("scope",claim)
			.build();

			JwtEncoderParameters jwtEncoderParameters=
			JwtEncoderParameters.from(
			JwsHeader.with(MacAlgorithm.HS512).build(),jwtClaimsSet);

			String jwt=jwtEncoder.encode(jwtEncoderParameters).getTokenValue();


        return jwt;
    }
}
