package com.doroshenko.serhey.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.time.Duration;
import java.util.UUID;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .scope("ALL")
                .scope(OidcScopes.OPENID)
                .clientId("user-service-client")
                .clientSecret("user-service-client-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenSettings(tokenSettings -> {
                    tokenSettings.reuseRefreshTokens(true);
                    tokenSettings.enableRefreshTokens(true);
                    tokenSettings.refreshTokenTimeToLive(Duration.ofDays(7));
                })
                .clientSettings(clientSettings -> clientSettings.requireUserConsent(true)).build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(final HttpSecurity http) throws Exception {
        applyDefaultSecurity(http);
        return http.build();
    }

    public static void applyDefaultSecurity(final HttpSecurity http) throws Exception {
        final var authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer<HttpSecurity>();
        final RequestMatcher[] endpointMatchers = authorizationServerConfigurer.getEndpointMatchers().toArray(new RequestMatcher[0]);

        http.requestMatcher(new OrRequestMatcher(endpointMatchers))
                .authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointMatchers))
                .apply(authorizationServerConfigurer);
    }

}
