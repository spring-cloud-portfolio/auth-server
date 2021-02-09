package com.doroshenko.serhey.auth.config;

import com.doroshenko.serhey.auth.service.crypto.KeyService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.UUID;

@Configuration(proxyBeanMethods = false)
@Import(OAuth2AuthorizationServerConfiguration.class)
public class AuthorizationServerConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .scope("ALL")
                .scope(OidcScopes.OPENID)
                .clientId("user-service-client")
                .clientSecret("user-service-client-secret")
                .redirectUri("http://localhost:8080/authorized")
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .clientSettings(clientSettings -> clientSettings.requireUserConsent(true)).build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(final KeyService keyService) {
        JWKSet jwkSet = new JWKSet(keyService.getRsaKey());
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

}
