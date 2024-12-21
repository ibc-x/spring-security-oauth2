package com.ic.ioauth2.controller;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ic.ioauth2.config.MyToken;
import com.ic.ioauth2.dto.LoginDTO;
import com.ic.ioauth2.dto.RegisterUserDTO;
import com.ic.ioauth2.model.CustomUser;
import com.ic.ioauth2.service.CustomUserService;




@RestController
@RequestMapping("/api/v1/auth")
public class SecurityController {


	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private CustomUserService customUserService;

	@Autowired
	private MyToken myToken;
	
	@GetMapping("/profile")
	Authentication authentication(Authentication authentication) {
		return authentication;
	}

	@PostMapping("/login")
	public Map<String, String> login(@RequestBody LoginDTO loginDTO){

		Map<String, String> response = new HashMap<>();
        try {
            UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDTO.getUsername(), loginDTO.getPassword());

            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            SecurityContextHolder.getContext().setAuthentication(authentication);

			Instant instant = Instant.now();
			
			String scope = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(" "));

			String jwt = myToken.generate(loginDTO.getUsername(), scope, instant, instant.plus(60, ChronoUnit.MINUTES));

            response.put("access-token", jwt);
            response.put("status", "200");
            return response;

        } catch (BadCredentialsException ex) {
            response.put("message", "Les identifications sont erronées");
            response.put("status", ""+HttpStatus.UNAUTHORIZED);
            return response;
        }
	
	}

	@PostMapping("/register")
	public Map<String, String> register(@RequestBody RegisterUserDTO registerUserDTO){
		CustomUser customUser = this.customUserService.creer(registerUserDTO);
		Instant instant = Instant.now();
		String scope = customUser.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(" "));
		String jwt=myToken.generate(customUser.getUsername(), scope, instant, instant.plus(60, ChronoUnit.MINUTES));
		return Map.of("access-token", jwt);
	}
		
}