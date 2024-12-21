package com.ic.ioauth2.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.ic.ioauth2.model.CustomUser;




public interface UserRepository extends JpaRepository<CustomUser, Long>{
    public CustomUser findByLogin(String username);
}
