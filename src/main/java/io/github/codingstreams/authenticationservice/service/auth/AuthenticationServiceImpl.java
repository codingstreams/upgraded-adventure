package io.github.codingstreams.authenticationservice.service.auth;

import io.github.codingstreams.authenticationservice.model.AppUser;
import io.github.codingstreams.authenticationservice.model.Role;
import io.github.codingstreams.authenticationservice.repository.AppUserRepo;
import io.github.codingstreams.authenticationservice.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {
  private final AuthenticationManager authenticationManager;
  private final PasswordEncoder passwordEncoder;
  private final AppUserRepo appUserRepo;

  @Override
  @Transactional
  public void createUser(String name, String username, String password) {
    // Encode password
    var encodedPassword = passwordEncoder.encode(password);

    // Create AppUser and save it in database
    var authorities = new ArrayList<GrantedAuthority>();
    authorities.add(new SimpleGrantedAuthority(Role.USER.getName()));

    var appUser = AppUser.builder()
        .name(name)
        .username(username)
        .password(encodedPassword)
        .authorities(authorities)
        .build();
    appUserRepo.save(appUser);

  }

  @Override
  public String login(String username, String password) {
    var authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
    var authenticate = authenticationManager.authenticate(authenticationToken);

    return JwtUtils.generateToken(((User)(authenticate.getPrincipal())).getUsername());
  }
}
