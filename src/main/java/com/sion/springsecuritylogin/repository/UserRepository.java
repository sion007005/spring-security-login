package com.sion.springsecuritylogin.repository;

import com.sion.springsecuritylogin.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
}
