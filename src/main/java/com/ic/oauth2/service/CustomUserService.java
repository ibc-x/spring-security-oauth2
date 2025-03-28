package com.ic.oauth2.service;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.ic.oauth2.dto.RegisterUserDTO;
import com.ic.oauth2.enumeration.Role;
import com.ic.oauth2.repository.UserRepository;

import lombok.RequiredArgsConstructor;



@Service
@RequiredArgsConstructor
public class CustomUserService implements UserDetailsService{

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
	com.ic.oauth2.model.User userEntity = userRepository.findByLogin(username);

	if (userEntity == null) {
		throw new UsernameNotFoundException("Utilisateur non trouvé: " + username);
	}

	return User.withUsername(userEntity.getLogin())
	.password(userEntity.getPassword())
	.roles(userEntity.getRole().name()).build();
	}

	public com.ic.oauth2.model.User creer(RegisterUserDTO registerUserDTO){
		com.ic.oauth2.model.User user = new com.ic.oauth2.model.User();
		user.setFullName(registerUserDTO.getFullName());
		user.setLogin(registerUserDTO.getUsername());
		user.setPassword(passwordEncoder.encode(registerUserDTO.getPassword()));
		user.setRole(Role.USER);
		return this.userRepository.save(user);
	}

}
