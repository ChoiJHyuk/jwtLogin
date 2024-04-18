package com.rosoa0475.jwt.repository;

import com.rosoa0475.jwt.entity.RefreshEntity;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshRepository extends JpaRepository<RefreshEntity, Long> {
    Boolean existsByRefresh(String refresh);

    @Transactional // 성공적으로 처리되면 commit하고 도중에 오류 발생 시 rollback해주는 어노테이션
    void deleteByRefresh(String refresh);
}
