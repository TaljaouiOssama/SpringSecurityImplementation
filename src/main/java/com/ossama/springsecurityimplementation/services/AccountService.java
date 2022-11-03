package com.ossama.springsecurityimplementation.services;


import com.ossama.springsecurityimplementation.entities.AppRole;
import com.ossama.springsecurityimplementation.entities.AppUser;

import java.util.List;

public interface AccountService {
    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String userName,String roleName);
    AppUser loadUserByUserName(String userName);
    List<AppUser> getAllUsers();

}
