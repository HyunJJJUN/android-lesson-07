package kr.easw.lesson07.service;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Random;

@Service
public class JwtService {
    private static final String STRING_COLLECTION = "0123456789abcdefghijklmnopqrstuvwxyz_+-=~";
    private static final Random RANDOM = new Random();
    private final SecretKey initialJwtSecret = Keys.hmacShaKeyFor(generateRandomString(64).getBytes(StandardCharsets.UTF_8));
    private final JwtParser jwtParser = Jwts.parser().verifyWith(initialJwtSecret).build();
    private final int jwtExpire = 60 * 60 * 1000;

    private String generateRandomString(int length) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < length; i++) {
            builder.append(STRING_COLLECTION.charAt(RANDOM.nextInt(STRING_COLLECTION.length())));
        }
        return builder.toString();
    }

    public String generateToken(String user) {
        return Jwts.builder()
                .subject(user)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtExpire))
                .signWith(initialJwtSecret, Jwts.SIG.HS512)
                .compact();
    }

    public ValidateStatus validate(String token) {
        try {
            jwtParser.parseSignedClaims(token).getPayload();
            return ValidateStatus.VALID;
        } catch (ExpiredJwtException ex) {
            return ValidateStatus.EXPIRED;
        } catch (UnsupportedJwtException ex) {
            return ValidateStatus.UNSUPPORTED;
        } catch (Exception ex) {
            return ValidateStatus.INVALID;
        }
    }

    public String extractUsername(String token) {
        return jwtParser.parseSignedClaims(token).getPayload().getSubject();
    }

    @Getter
    @RequiredArgsConstructor
    public enum ValidateStatus {
        VALID(true), INVALID(false), EXPIRED(false), UNSUPPORTED(false);
        private final boolean valid;
    }
}
