package io.github.codingstreams.authenticationservice.configuration;

import io.github.codingstreams.authenticationservice.util.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
  private final UserDetailsService userDetailsService;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    // Get token from request
    String token = getTokenFromRequest(request);

    // Validate token using JWT provider
    if (token != null && JwtUtils.validateToken(token)) {

      // Get username from token
      String username = JwtUtils.getUsernameFromToken(token);

      // Get user details
      UserDetails userDetails = userDetailsService.loadUserByUsername(username);

      // Create authentication object
      var auth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

      // Set user to Security Context
      SecurityContextHolder.getContext()
          .setAuthentication(auth);
    }

    // Pass to next filter
    filterChain.doFilter(request, response);
  }

  private String getTokenFromRequest(HttpServletRequest request) {
    // Extract authentication header
    var authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

    // Check whether it starts with `Bearer ` or not
    if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
      return authHeader.substring(7);
    }

    return null;
  }
}
