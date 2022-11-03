package com.ossama.springsecurityimplementation.contollers.api;

import com.ossama.springsecurityimplementation.entities.AppRole;
import com.ossama.springsecurityimplementation.entities.AppUser;
import com.ossama.springsecurityimplementation.entities.RoleUserDto;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.awt.*;
import java.util.List;

public interface AccountController {
    @PostMapping(value = "/users",consumes = MediaType.APPLICATION_JSON_VALUE,produces = MediaType.APPLICATION_JSON_VALUE)
    @PostAuthorize("hasAuthority('admin')")
    AppUser saveUser(@RequestBody AppUser appUser);
    @PostMapping(value = "/roles",consumes = MediaType.APPLICATION_JSON_VALUE,produces = MediaType.APPLICATION_JSON_VALUE)
    @PostAuthorize("hasAuthority('admin')")
    AppRole saveRole(@RequestBody AppRole appRole);
    @PostMapping(value = "/addRoleToUser",consumes = MediaType.APPLICATION_JSON_VALUE,produces = MediaType.APPLICATION_JSON_VALUE)
    @PostAuthorize("hasAuthority('admin')")
    void  addRoleToUser(@RequestBody RoleUserDto roleUserDto);
    @GetMapping(value = "/users",produces = MediaType.APPLICATION_JSON_VALUE)
     List<AppUser> appUserList();

    @GetMapping(value = "/refreshToken")
    void refreshToken(HttpServletRequest request, HttpServletResponse response)throws Exception;

}
