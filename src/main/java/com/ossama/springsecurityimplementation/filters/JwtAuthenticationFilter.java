package com.ossama.springsecurityimplementation.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private AuthenticationManager authenticationManager;
    @Autowired
    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("attemptAuthentication");
        String username=request.getParameter("username");
       String password=request.getParameter("password");
        UsernamePasswordAuthenticationToken authenticationToken=new UsernamePasswordAuthenticationToken(username,password);
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication");
        User user=(User) authResult.getPrincipal();
        Algorithm alg=Algorithm.HMAC256("secret");
        String jwtAccessToken= JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+1000*60*1))
                .withIssuer(request.getRequestURL().toString())
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .withClaim("roles",user.getAuthorities().stream().map(at->at.getAuthority()).collect(Collectors.toList()))
                .sign(alg);
        String jwtRefreshToken= JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+1000*60*15))
                .withIssuer(request.getRequestURL().toString())
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .sign(alg);
        Map<String,String> idToken=new HashMap<>();
        idToken.put("jwtRefreshToken",jwtRefreshToken);
        idToken.put("jwtAccessToken",jwtAccessToken);
        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(),idToken);

    }
}
