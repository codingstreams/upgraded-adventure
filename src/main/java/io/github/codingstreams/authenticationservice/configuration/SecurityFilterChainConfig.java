package io.github.codingstreams.authenticationservice.configuration;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@EnableWebSecurity
@Configuration
public class SecurityFilterChainConfig {
  @Qualifier("customAuthenticationEntryPoint")
  private final AuthenticationEntryPoint authenticationEntryPoint;
  private final JwtAuthenticationFilter jwtAuthenticationFilter;
  private final AuthenticationProvider authenticationProvider;

  public SecurityFilterChainConfig(AuthenticationEntryPoint authenticationEntryPoint, JwtAuthenticationFilter jwtAuthenticationFilter, AuthenticationProvider authenticationProvider) {
    this.authenticationEntryPoint = authenticationEntryPoint;
    this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    this.authenticationProvider = authenticationProvider;
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
    // Disable CORS
    httpSecurity.cors(corsConfig -> corsConfig.configurationSource(getConfigurationSource()));

    // Disable CSRF
    httpSecurity.csrf(AbstractHttpConfigurer::disable);

    // Http Requests Filter
    httpSecurity.authorizeHttpRequests(requestMatcher -> requestMatcher
        .requestMatchers("/api/auth/login/**").permitAll()
        .requestMatchers("/api/auth/sign-up/**").permitAll()
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

    // Set Authentication Provider
    httpSecurity.authenticationProvider(authenticationProvider);

    // Add JWT Filter before UsernamePasswordAuthenticationFilter
    httpSecurity.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

    return httpSecurity.build();
  }

  private static UrlBasedCorsConfigurationSource getConfigurationSource() {
    var corsConfiguration = new CorsConfiguration();
    corsConfiguration.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
    corsConfiguration.setAllowedOrigins(List.of("http://192.168.0.101:3000/"));
    corsConfiguration.addAllowedHeader("Content-Type");

    var source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", corsConfiguration);
    return source;
  }
}
