package gr.atc.urbreath.util;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

class JwtUtilsTest {
    private static Jwt jwt;

    @BeforeAll
    @SuppressWarnings("unused")
    static void setup() {
        String tokenValue = "mock.jwt.token";
        Map<String, Object> claims = new HashMap<>();
        claims.put("realm_access", Map.of("roles", List.of("SUPER_ADMIN")));
        claims.put("resource_access", Map.of("urbreath", Map.of("roles", List.of("ADMIN"))));
        claims.put("sub", "user123");
        claims.put("pilot_code", "TEST_PILOT");
        claims.put("pilot_role", "PILOT_ROLE_TEST");

        jwt = Jwt.withTokenValue(tokenValue)
                .headers(header -> header.put("alg", "HS256"))
                .claims(claim -> claim.putAll(claims))
                .build();
    }

    @DisplayName("Extract pilot code: Success")
    @Test
    void givenJwt_whenExtractPilotCode_thenReturnPilotCode() {
        // When
        String pilotCode = JwtUtils.extractPilotCode(jwt);

        // Then
        assertNotNull(pilotCode);
        assertEquals("TEST_PILOT", pilotCode);
    }

    @DisplayName("Extract pilot code: Null when no pilot field")
    @Test
    void givenJwtWithoutPilot_whenExtractPilotCode_thenReturnNull() {
        // Given
        Jwt jwtWithoutPilot = Jwt.withTokenValue("token")
                .headers(header -> header.put("alg", "HS256"))
                .claims(claims -> claims.put("pilot", null))
                .build();

        // When
        String pilotCode = JwtUtils.extractPilotCode(jwtWithoutPilot);

        // Then
        assertNull(pilotCode);
    }

    @DisplayName("Extract user ID: Success")
    @Test
    void givenJwt_whenExtractUserId_thenReturnUserId() {
        // When
        String userId = JwtUtils.extractUserId(jwt);

        // Then
        assertNotNull(userId);
        assertEquals("user123", userId);
    }

    @DisplayName("Extract user ID: Null when no ID field")
    @Test
    void givenJwtWithoutUserId_whenExtractUserId_thenReturnNull() {
        // Given
        Jwt jwtWithoutUserId = Jwt.withTokenValue("token")
                .headers(header -> header.put("alg", "HS256"))
                .claims(claims -> claims.put("sub", null))
                .build();

        // When
        String userId = JwtUtils.extractUserId(jwtWithoutUserId);

        // Then
        assertNull(userId);
    }

    @DisplayName("Extract pilot role: Success")
    @Test
    void givenJwt_whenExtractPilotRole_thenReturnPilotRole() {
        // When
        String pilotRole = JwtUtils.extractPilotRole(jwt);

        // Then
        assertNotNull(pilotRole);
        assertEquals("PILOT_ROLE_TEST", pilotRole);
    }


    @DisplayName("Extract pilot role: Null when no pilot role field")
    @Test
    void givenJwtWithoutPilotRole_whenExtractPilotRole_thenReturnNull() {
        // Given
        Jwt jwtWithoutPilotRole = Jwt.withTokenValue("token")
                .headers(header -> header.put("alg", "HS256"))
                .claims(claims -> claims.put("pilot_role", null))
                .build();

        // When
        String pilotRole = JwtUtils.extractPilotRole(jwtWithoutPilotRole);

        // Then
        assertNull(pilotRole);
    }


    @DisplayName("Extract user type: Empty when no roles in resource access")
    @Test
    void givenJwtWithoutResourceRoles_whenExtractUserType_thenReturnEmptyList() {
        // Given
        Jwt jwtWithoutRoles = Jwt.withTokenValue("token")
                .headers(header -> header.put("alg", "HS256"))
                .claims(claims -> claims.put("resource_access", Map.of("urbreath", Map.of())))
                .build();

        // When
        List<String> userTypes = JwtUtils.extractUserType(jwtWithoutRoles);

        // Then
        assertTrue(userTypes.isEmpty());
    }

    @DisplayName("Extract user type: Null JWT")
    @Test
    void givenNullJwt_whenExtractUserType_thenReturnEmptyList() {
        // When
        List<String> userTypes = JwtUtils.extractUserType(null);

        // Then
        assertTrue(userTypes.isEmpty());
    }
}
