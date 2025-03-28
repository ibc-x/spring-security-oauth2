package com.ic.oauth2.config;

import java.text.MessageFormat;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import com.ic.oauth2.dto.TokenDTO;

import lombok.RequiredArgsConstructor;


@Service
@RequiredArgsConstructor
public class TokenGenerator {

	private final JwtEncoder jwtEncoder;

    /**
     * @param subject entity / utilisateur
     * @param claim  les authorisations de l'utilisateur
     * @param expiresAt  Date et heure d'expiration du token
     * @return String
     */
    public String generate(String subject, String claim, Instant expiresAt){

            JwtClaimsSet jwtClaimsSet=JwtClaimsSet.builder()
			.issuedAt(Instant.now())
			.expiresAt(expiresAt)
			.subject(subject)
			.claim("scope",claim)
			.build();

			JwtEncoderParameters jwtEncoderParameters=
			JwtEncoderParameters.from(
			JwsHeader.with(MacAlgorithm.HS512).build(),jwtClaimsSet);

			return jwtEncoder.encode(jwtEncoderParameters).getTokenValue();
    }

    private String createAccessToken(Authentication authentication) {
        String name = authentication.getName();
        String scope = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(" "));
        Instant now = Instant.now();
        return generate(name, scope, now.plus(60, ChronoUnit.MINUTES));
    }

    private String createRefreshToken(Authentication authentication) {
        String name = authentication.getName();
        String scope = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(" "));
        Instant now = Instant.now();
        return generate(name, scope, now.plus(30, ChronoUnit.DAYS));
    }

    public TokenDTO createToken(Authentication authentication) {
        if (!(authentication.getPrincipal() instanceof User)) {
            throw new BadCredentialsException(
                    MessageFormat.format("principal {0} is not of User type ", authentication.getPrincipal().getClass())
            );
        }

        TokenDTO tokenDTO = new TokenDTO();
        tokenDTO.setAccessToken(createAccessToken(authentication));

        String refreshToken;
        if (authentication.getCredentials() instanceof Jwt jwt) {
            Instant now = Instant.now();
            Instant expiresAt = jwt.getExpiresAt();
            Duration duration = Duration.between(now, expiresAt);
            long daysUntilExpired = duration.toDays();
            if (daysUntilExpired < 7) {
                refreshToken = createRefreshToken(authentication);
            } else {
                refreshToken = jwt.getTokenValue();
            }
        } else {
            refreshToken = createRefreshToken(authentication);
        }
        tokenDTO.setRefreshToken(refreshToken);

        return tokenDTO;
    }
}
