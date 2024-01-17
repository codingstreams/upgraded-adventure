package io.github.codingstreams.authenticationservice.controller;

import io.github.codingstreams.authenticationservice.dto.AuthRequestDto;
import io.github.codingstreams.authenticationservice.dto.AuthResponseDto;
import io.github.codingstreams.authenticationservice.dto.AuthStatus;
import io.github.codingstreams.authenticationservice.service.auth.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
  private final AuthenticationService authenticationService;

  @PostMapping("/login")
  public ResponseEntity<AuthResponseDto> login(@RequestBody AuthRequestDto authRequestDto) {
    var token = authenticationService.login(authRequestDto.username(), authRequestDto.password());

    var authResponseDto = new AuthResponseDto(token, AuthStatus.LOGIN_SUCCESS);

    return ResponseEntity
        .status(HttpStatus.OK)
        .body(authResponseDto);
  }

  @PostMapping("/sign-up")
  public ResponseEntity<AuthResponseDto> signUp(@RequestBody AuthRequestDto authRequestDto) {
    authenticationService.createUser(authRequestDto.name(), authRequestDto.username(), authRequestDto.password());

    var authResponseDto = new AuthResponseDto(null, AuthStatus.USER_CREATED_SUCCESSFULLY);

    return ResponseEntity
        .status(HttpStatus.OK)
        .body(authResponseDto);
  }

  @GetMapping("/verify-token")
  public ResponseEntity<AuthResponseDto> verifyToken() {
    var authResponseDto = new AuthResponseDto(null, AuthStatus.TOKEN_VALID);

    return ResponseEntity
        .status(HttpStatus.OK)
        .body(authResponseDto);
  }
}
