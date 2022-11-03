package com.ossama.springsecurityimplementation.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class JwtAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorizationToken=request.getHeader("Authorization");
        if(request.getServletPath().equals("/refreshToken")){
            filterChain.doFilter(request,response);
        }
        else{
            if(authorizationToken!=null && authorizationToken.startsWith("Bearer")){
                try {
                    String jwtToken=authorizationToken.substring(7);
                    Algorithm alg=Algorithm.HMAC256("secret");
                    JWTVerifier jwtVerifier= JWT.require(alg).build();
                    DecodedJWT decodedJWT=jwtVerifier.verify(jwtToken);
                    String username=decodedJWT.getSubject();
                    List<String> roles= decodedJWT.getClaim("roles").asList(String.class);
                    UsernamePasswordAuthenticationToken authenticationToken=new UsernamePasswordAuthenticationToken(
                            username,null,roles.stream().map(r->new SimpleGrantedAuthority(r)).collect(Collectors.toList())
                    );
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    filterChain.doFilter(request,response);
                } catch (Exception e) {
                    response.setHeader("error-message",e.getMessage());
                    response.sendError(HttpServletResponse.SC_FORBIDDEN);
                }
            }
            else{
                filterChain.doFilter(request,response);
            }
        }
    }
}
