package io.github.codingstreams.authenticationservice.configuration;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@Configuration
public class SecurityConfig {
  @Qualifier("customAuthenticationEntryPoint")
  private final AuthenticationEntryPoint authenticationEntryPoint;
  private final JwtAuthenticationFilter jwtAuthenticationFilter;

  public SecurityConfig(AuthenticationEntryPoint authenticationEntryPoint, JwtAuthenticationFilter jwtAuthenticationFilter) {
    this.authenticationEntryPoint = authenticationEntryPoint;
    this.jwtAuthenticationFilter = jwtAuthenticationFilter;
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
    // Disable CORS
    httpSecurity.cors(AbstractHttpConfigurer::disable);

    // Disable CSRF
    httpSecurity.csrf(AbstractHttpConfigurer::disable);

    // Http Requests Filter
    httpSecurity.authorizeHttpRequests(requestMatcher -> requestMatcher
        .requestMatchers("/api/auth/**").permitAll()
        .anyRequest().authenticated()
    );

    // Add Authentication Entry Point -> For Exception Handling
    httpSecurity.exceptionHandling(exceptionHandlingConfigurer ->
        exceptionHandlingConfigurer.authenticationEntryPoint(authenticationEntryPoint)
    );

    // Set Session Policy = STATELESS
    httpSecurity.sessionManagement(sessionConfigure ->
        sessionConfigure.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
    );

    // Add JWT Filter before UsernamePasswordAuthenticationFilter
    httpSecurity.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

    return httpSecurity.build();
  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationProvider... authenticationProviders) {
   return new ProviderManager(authenticationProviders);
  }

  @Bean
  public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
    var daoAuthenticationProvider = new DaoAuthenticationProvider();
    daoAuthenticationProvider.setUserDetailsService(userDetailsService);
    daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);

    return daoAuthenticationProvider;
  }

  @Bean
  public PasswordEncoder bCryptPasswordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
