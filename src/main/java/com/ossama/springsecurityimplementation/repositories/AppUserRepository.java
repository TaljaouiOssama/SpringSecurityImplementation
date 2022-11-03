package com.ossama.springsecurityimplementation.repositories;

import com.ossama.springsecurityimplementation.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser,Long> {
    AppUser findAppUsersByUsername(String username);

}
