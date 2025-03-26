package gr.atc.urbreath.keycloak;

import java.util.*;
import java.util.stream.Collectors;
import static java.util.stream.Collectors.toList;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter=new JwtGrantedAuthoritiesConverter();

    private static final String CLAIM_REALM_ACCESS = "realm_access";
    private static final String CLAIM_RESOURCE_ACCESS = "resource_access";
    private static final String CLAIM_ROLES = "roles";

    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) throws NullPointerException {
        Collection<GrantedAuthority> authorities = Stream.concat(
          Optional.of(jwtGrantedAuthoritiesConverter.convert(jwt)).orElseGet(Collections::emptyList).stream(),
                extractKeycloakRoles(jwt).stream()
        ).collect(Collectors.toSet());

        return new JwtAuthenticationToken(jwt, authorities,jwt.getClaim("preferred_username"));
    }

    private Collection<GrantedAuthority> extractKeycloakRoles(Jwt jwt) {
        try {
            Set<String> roles = new HashSet<>();

            // Extract realm roles
            Map<String, Object> realmAccess = jwt.getClaim(CLAIM_REALM_ACCESS);
            if (realmAccess != null) {
                roles.addAll(extractRolesFromClaim(realmAccess));
            }

            // Extract resource roles
            Map<String, Object> resourceAccess = jwt.getClaim(CLAIM_RESOURCE_ACCESS);
            if (resourceAccess != null) {
                    resourceAccess.values().stream()
                            .filter(Map.class::isInstance)
                            .map(obj -> (Map<String, Object>) obj)
                            .map(this::extractRolesFromClaim)
                            .forEach(roles::addAll);
            }

            return roles.stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .collect(toList());

        }catch (Exception e){
            return Collections.emptyList();
        }
    }

    private List<String> extractRolesFromClaim(Map<String, Object> claimMap) {
        Object rolesObj = claimMap.get(CLAIM_ROLES);
        if (rolesObj instanceof List<?>) {
            return ((List<?>) rolesObj).stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .toList();
        }
        return Collections.emptyList();
    }


}