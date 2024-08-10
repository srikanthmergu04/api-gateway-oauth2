package com.learning.api_gateway.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello(Authentication authentication) {

        String name = "";
        if(authentication instanceof OAuth2AuthenticationToken oAuth2AuthenticationToken){
            name = oAuth2AuthenticationToken.getPrincipal().getAttributes().get("name").toString();
        }else if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken){
            Jwt jwt = (Jwt) jwtAuthenticationToken.getPrincipal();
            name = jwt.getClaims().get("name").toString();
        }

        return "Hello "+name;
    }

}
