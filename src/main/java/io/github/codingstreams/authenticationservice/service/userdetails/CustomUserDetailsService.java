package io.github.codingstreams.authenticationservice.service.userdetails;

import io.github.codingstreams.authenticationservice.repository.AppUserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
  private final AppUserRepo appUserRepo;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    var appUser = appUserRepo.findByUsername(username)
        .orElseThrow();
    return new User(appUser.getUsername(), appUser.getPassword(), appUser.getAuthorities());
  }
}
