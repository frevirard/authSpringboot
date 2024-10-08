package com.example.creato.webConfig;

import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.example.creato.jwt.JwtRequestFilter;
import com.example.creato.users.CustomUserDetailsService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;

@Configuration
public class WebSecurityConfig {

    @Autowired
    private CustomUserDetailsService myUserDetailsService;

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(this.myUserDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    // @Bean
    // public AuthenticationManager
    // authenticationManager(AuthenticationConfiguration config) throws Exception {
    // return config.getAuthenticationManager();
    // }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Disable CSRF for simplicity (not recommended for production)
                .csrf().disable()
                // Authorize requests
                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/", "/home", "/public/**").permitAll() // Public endpoints
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/auth/signin").permitAll()
                        .requestMatchers("/fred").permitAll()
                        .requestMatchers("/inMemory").permitAll()
                        .requestMatchers("/createRoles").permitAll()
                        .anyRequest().authenticated() // All other endpoints require authentication
                )
                // Form-based login configuration
                .formLogin(AbstractAuthenticationFilterConfigurer::permitAll)
                // .addFilterBefore(authenticationJwtTokenFilter(),
                // UsernamePasswordAuthenticationFilter.class)

                // Logout configuration
                .logout((logout) -> logout.permitAll());

        return http.build();
    }

    // Define a PasswordEncoder bean
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
