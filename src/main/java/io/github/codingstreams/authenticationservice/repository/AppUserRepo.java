package io.github.codingstreams.authenticationservice.repository;

import io.github.codingstreams.authenticationservice.model.AppUser;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface AppUserRepo extends MongoRepository<AppUser, String> {
  Optional<AppUser> findByUsername(String username);
}
