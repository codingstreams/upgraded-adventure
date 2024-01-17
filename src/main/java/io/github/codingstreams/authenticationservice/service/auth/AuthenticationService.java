package io.github.codingstreams.authenticationservice.service.auth;


public interface AuthenticationService {
  void createUser(String name, String username, String password);

  String login(String username, String password);
}
