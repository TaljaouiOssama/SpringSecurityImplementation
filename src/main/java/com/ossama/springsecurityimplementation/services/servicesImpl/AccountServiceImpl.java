package com.ossama.springsecurityimplementation.services.servicesImpl;

import com.ossama.springsecurityimplementation.entities.AppRole;
import com.ossama.springsecurityimplementation.entities.AppUser;
import com.ossama.springsecurityimplementation.repositories.AppRoleRepository;
import com.ossama.springsecurityimplementation.repositories.AppUserRepository;
import com.ossama.springsecurityimplementation.services.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
@Service
@Transactional
public class AccountServiceImpl implements AccountService {
    private AppRoleRepository appRoleRepository;
    private AppUserRepository appUserRepository;
    private PasswordEncoder passwordEncoder;
    @Autowired
    public AccountServiceImpl(AppRoleRepository appRoleRepository, AppUserRepository appUserRepository, PasswordEncoder passwordEncoder) {
        this.appRoleRepository = appRoleRepository;
        this.appUserRepository = appUserRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public AppUser addNewUser(AppUser appUser) {
        appUser.setPassword(passwordEncoder.encode(appUser.getPassword()));
        return appUserRepository.save(appUser);
    }

    @Override
    public AppRole addNewRole(AppRole appRole) {
        return appRoleRepository.save(appRole);
    }

    @Override
    public void addRoleToUser(String userName, String roleName) {
        AppUser user=appUserRepository.findAppUsersByUsername(userName);
        AppRole role=appRoleRepository.findAppRoleByRoleName(roleName);
        user.getRoles().add(role);
        appUserRepository.save(user);
    }

    @Override
    public AppUser loadUserByUserName(String userName) {
        return appUserRepository.findAppUsersByUsername(userName);
    }

    @Override
    public List<AppUser> getAllUsers() {
        return appUserRepository.findAll();
    }
}
