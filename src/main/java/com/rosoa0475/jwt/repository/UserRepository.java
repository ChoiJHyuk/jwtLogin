package com.rosoa0475.jwt.repository;

import com.rosoa0475.jwt.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {
    public Boolean existsByUsername(String username);

    UserEntity findByUsername(String username);
}
