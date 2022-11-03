package com.ossama.springsecurityimplementation.contollers.api.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ossama.springsecurityimplementation.contollers.api.AccountController;
import com.ossama.springsecurityimplementation.entities.AppRole;
import com.ossama.springsecurityimplementation.entities.AppUser;
import com.ossama.springsecurityimplementation.entities.RoleUserDto;
import com.ossama.springsecurityimplementation.services.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AccountControllerImpl implements AccountController {
    private AccountService accountService;
    @Autowired
    public AccountControllerImpl(AccountService accountService) {
        this.accountService = accountService;
    }

    @Override
    public AppUser saveUser(AppUser appUser) {
        return accountService.addNewUser(appUser);
    }

    @Override
    public AppRole saveRole(AppRole appRole) {
        return accountService.addNewRole(appRole);
    }

    @Override
    public void addRoleToUser(RoleUserDto roleUserDto) {
        accountService.addRoleToUser(roleUserDto.getUser(),roleUserDto.getRole());
        return;
    }

    @Override
    public List<AppUser> appUserList() {
        return this.accountService.getAllUsers();
    }

    @Override
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws Exception{
        String authorizationToken=request.getHeader("Authorization");
        if(authorizationToken!=null && authorizationToken.startsWith("Bearer")){
            try {
                String jwtToken=authorizationToken.substring(7);
                Algorithm alg=Algorithm.HMAC256("secret");
                JWTVerifier jwtVerifier= JWT.require(alg).build();
                DecodedJWT decodedJWT=jwtVerifier.verify(jwtToken);
                String username=decodedJWT.getSubject();
                AppUser appUser=this.accountService.loadUserByUserName(username);
                String jwtAccessToken= JWT.create()
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis()+1000*60*1))
                        .withIssuer(request.getRequestURL().toString())
                        .withIssuedAt(new Date(System.currentTimeMillis()))
                        .withClaim("roles",appUser.getRoles().stream().map(r->r.getRoleName()).collect(Collectors.toList()))
                        .sign(alg);
                Map<String,String> idToken=new HashMap<>();
                idToken.put("jwtRefreshToken",jwtToken);
                idToken.put("jwtAccessToken",jwtAccessToken);
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(),idToken);

            } catch (Exception e) {
               throw e;
            }
        }
    }
}
