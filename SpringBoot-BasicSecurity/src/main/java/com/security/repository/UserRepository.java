package com.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.security.model.User;

public interface UserRepository extends JpaRepository<User, Long>{

	User findByUserName(String username);

}
