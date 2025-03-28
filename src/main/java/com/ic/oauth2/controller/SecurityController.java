package com.ic.oauth2.controller;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ic.oauth2.config.TokenGenerator;
import com.ic.oauth2.dto.LoginDTO;
import com.ic.oauth2.dto.RegisterUserDTO;
import com.ic.oauth2.dto.TokenDTO;
import com.ic.oauth2.model.User;
import com.ic.oauth2.service.CustomUserService;

import lombok.RequiredArgsConstructor;




@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class SecurityController {

	private final AuthenticationManager authenticationManager;


	private final CustomUserService customUserService;


	private final TokenGenerator tokenGenerator;


	@Qualifier("jwtRefreshTokenAuthProvider")
	private final JwtAuthenticationProvider refreshTokenAuthProvider;
	
	@GetMapping("/profile")
	Authentication authentication(Authentication authentication) {
		System.out.println("type principal:  "+authentication.getPrincipal().getClass());
		return authentication;
	}

	@PostMapping("/login")
	public ResponseEntity<TokenDTO> login(@RequestBody LoginDTO loginDTO){

		UsernamePasswordAuthenticationToken authenticationToken =
				new UsernamePasswordAuthenticationToken(loginDTO.getUsername(), loginDTO.getPassword());

		Authentication authentication = authenticationManager.authenticate(authenticationToken);
		
		SecurityContextHolder.getContext().setAuthentication(authentication);

		TokenDTO tokenDTO = tokenGenerator.createToken(authentication);
		return ResponseEntity.ok(tokenDTO);
	}

	@PostMapping("/register")
	public Map<String, String> register(@RequestBody RegisterUserDTO registerUserDTO){
		User customUser = this.customUserService.creer(registerUserDTO);
		Instant instant = Instant.now();
		String scope = customUser.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(" "));
		String jwt=tokenGenerator.generate(customUser.getUsername(), scope, instant.plus(60, ChronoUnit.MINUTES));
		return Map.of("access-token", jwt);
	}

	@PostMapping("/refresh")
    public ResponseEntity<TokenDTO> refresh(@RequestBody TokenDTO tokenDto) {
      Authentication authentication = refreshTokenAuthProvider.authenticate(new BearerTokenAuthenticationToken(tokenDto.getRefreshToken()));
      TokenDTO tokenDTO = tokenGenerator.createToken(authentication);
		return ResponseEntity.ok(tokenDTO);
    }
		
}