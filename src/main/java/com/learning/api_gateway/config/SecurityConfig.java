package com.learning.api_gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.server.SecurityWebFilterChain;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .authorizeExchange(authorize -> authorize
                        .pathMatchers("/hello").hasRole("admin")
                        .anyExchange().authenticated()
                )
                .oauth2Login(withDefaults());

        return http.build();
    }

    @Bean
    public GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return (authorities) -> {
            AtomicReference<Set<GrantedAuthority>> mappedAuthorities = new AtomicReference<>(new HashSet<>());

            authorities.forEach(authority -> {
                if (OidcUserAuthority.class.isInstance(authority)) {
                    OidcUserAuthority oidcUserAuthority = (OidcUserAuthority) authority;

                    OidcUserInfo userInfo = oidcUserAuthority.getUserInfo();

                    List<String> roles = (List<String>) userInfo.getClaimAsMap("realm_access").get("roles");

                    mappedAuthorities.set(roles
                            .stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role)).collect(Collectors.toSet()));


                } else if (OAuth2UserAuthority.class.isInstance(authority)) {
                    OAuth2UserAuthority oauth2UserAuthority = (OAuth2UserAuthority) authority;

                    Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();

                }
            });

            return mappedAuthorities.get();
        };
    }

}
