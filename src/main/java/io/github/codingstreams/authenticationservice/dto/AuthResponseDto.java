package io.github.codingstreams.authenticationservice.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record AuthResponseDto(String token, AuthStatus status) {
}
