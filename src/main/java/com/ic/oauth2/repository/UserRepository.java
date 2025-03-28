package com.ic.oauth2.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.ic.oauth2.model.User;



public interface UserRepository extends JpaRepository<User, Long>{
    public User findByLogin(String username);
}
