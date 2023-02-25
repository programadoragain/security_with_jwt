package com.ferdev.Security.Security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class WebSecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        return http
                .csrf().disable()
                .authorizeHttpRequests().anyRequest().authenticated()
                .and()
                .httpBasic()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .build();
    }

    @Bean
    UserDetailsService userDetailsService(){
        InMemoryUserDetailsManager manager= new InMemoryUserDetailsManager();

        manager.createUser(User.withUsername("admin")
            .password(passwordEncoder().encode("admin"))
            .roles()
            .build());

        return manager;
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    // C
    @Bean
    AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(userDetailsService())
                .passwordEncoder(passwordEncoder())
                .and().build();
    }

    /**
     * @Configuration
     * @EnableWebSecurity
     * @EnableMethodSecurity(prePostEnabled = false, securedEnabled = true)
     * public class SecurityConfig {
     *
     *     private final PersonDetailsService personDetailsService;
     *
     *     @Autowired
     *     public SecurityConfig(PersonDetailsService personDetailsService) {
     *         this.personDetailsService = personDetailsService;
     *     }
     *
     *     @Bean
     *     public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
     *         return authenticationConfiguration.getAuthenticationManager();
     *     }
     *
     *     @Bean
     *     public PasswordEncoder passwordEncoder() {
     *         return new BCryptPasswordEncoder();
     *     }
     *
     *     @Bean
     *     public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
     *         http.cors().and().csrf().disable().authorizeHttpRequests(authorize -> authorize
     *                         .requestMatchers("/, /login, /signup, /logout").permitAll()
     *                 .requestMatchers("/api").hasRole("ADMIN")
     *                 .requestMatchers("/user").hasRole("USER")
     *                 .anyRequest().authenticated())
     *                 .logout().logoutUrl("/logout").logoutSuccessUrl("/").and()
     *                 .formLogin().loginPage("/login").loginProcessingUrl("/login").defaultSuccessUrl("/user").failureUrl("/login?error");
     *         return http.build();
     *     }
     * }
     */
}