package io.github.codingstreams.authenticationservice.util;

import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.time.DateUtils;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.UUID;

@Slf4j
public class JwtUtils {
  private static final String CODING_STREAMS_AUTH_SERVER = "coding_streams_auth_server";
  private static final SecretKey secretKey = Jwts.SIG.HS256.key().build();

  public static String generateToken(String username) {
    // Generate token
    var currentDate = new Date();
    var jwtExpirationInMinutes = 5;
    var expiration = DateUtils.addMinutes(currentDate, jwtExpirationInMinutes);

    return Jwts.builder()
        .id(UUID.randomUUID().toString())
        .issuer(CODING_STREAMS_AUTH_SERVER)
        .subject(username)
        .signWith(secretKey)
        .issuedAt(currentDate)
        .expiration(expiration)
        .compact();
  }

  private static Claims parseToken(String token) {
    // Create JwtParser
    JwtParser jwtParser = Jwts.parser()
        .verifyWith(secretKey)
        .build();

    try {
      return jwtParser
          .parseSignedClaims(token)
          .getPayload();
    } catch (UnsupportedJwtException | MalformedJwtException | IllegalArgumentException e) {
      log.error("[parseToken] - ERROR - {}", e.getMessage());
    }

    return null;
  }

  public static boolean validateToken(String token) {
    return parseToken(token) != null;
  }

  public static String getUsernameFromToken(String token) {
    // Get claims
    Claims claims = parseToken(token);

    // Extract subject
    if (claims != null) {
      return claims.getSubject();
    }

    return null;
  }
}
