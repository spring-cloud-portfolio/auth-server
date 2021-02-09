package com.doroshenko.serhey.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class DefaultSecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.withUsername("user1").password("{noop}password1").roles("USER").build(),
                User.withUsername("user2").password("{noop}password2").roles("USER").build(),
                User.withUsername("user3").password("{noop}password3").roles("USER").build()
        );
    }

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(final HttpSecurity http) throws Exception {
        return http.formLogin(Customizer.withDefaults())
                .authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
                .build();
    }

}
