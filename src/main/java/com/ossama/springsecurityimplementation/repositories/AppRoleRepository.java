package com.ossama.springsecurityimplementation.repositories;

import com.ossama.springsecurityimplementation.entities.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppRoleRepository extends JpaRepository<AppRole,Long> {
    AppRole findAppRoleByRoleName(String roleName);
}
