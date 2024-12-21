package com.ic.ioauth2.service;
// import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Bean;
// import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.ic.ioauth2.dto.RegisterUserDTO;
import com.ic.ioauth2.enumeration.Role;
import com.ic.ioauth2.model.CustomUser;
import com.ic.ioauth2.repository.UserRepository;

import lombok.RequiredArgsConstructor;



@Service
@RequiredArgsConstructor
public class CustomUserService implements UserDetailsService{

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
	CustomUser userEntity = userRepository.findByLogin(username);

	if (userEntity == null) {
		throw new UsernameNotFoundException("Utilisateur non trouvé: " + username);
	}

	UserDetails userDetails = User.withUsername(userEntity.getLogin())
	.password(userEntity.getPassword())
	.roles(userEntity.getRole().name()).build();
	

	return userDetails;
	}

	public CustomUser creer(RegisterUserDTO registerUserDTO){
		CustomUser customUser = new CustomUser();
		customUser.setFullName(registerUserDTO.getFullName());
		customUser.setLogin(registerUserDTO.getUsername());
		customUser.setPassword(passwordEncoder.encode(registerUserDTO.getPassword()));
		customUser.setRole(Role.USER);
		return this.userRepository.save(customUser);
	}

	
	// @Bean
	// public CustomUser users() {
	// 	UserDetails user = User.builder()
	// 	.username("user")
	// 	.password(new BCryptPasswordEncoder()
	// 	.encode("password"))
	// 	.roles("USER")
	// 	.build();		
	// 	CustomUser cs = new CustomUser();
	// 	cs.setFullName("");
	// 	cs.setLogin(user.getUsername());
	// 	cs.setPassword(user.getPassword());
	// 	cs.setRole(Role.USER);

	// 	return this.userRepository.save(cs);
	// }
}
