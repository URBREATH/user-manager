package gr.atc.urbreath.service;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import gr.atc.urbreath.dto.keycloak.ClientRepresentationDTO;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import gr.atc.urbreath.dto.keycloak.GroupRepresentationDTO;
import static gr.atc.urbreath.exception.CustomExceptions.*;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

/**
 * We utilize this component to include some common functionalities for the Keycloak Requests
 */
@Service
@Slf4j
public class KeycloakSupportService {

    @Value("${keycloak.token-uri}")
    private String tokenUri;

    @Value("${keycloak.admin.uri}")
    private String adminUri;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.client-secret}")
    private String clientSecret;

    private final RestTemplate restTemplate = new RestTemplate();

    // Strings commonly used
    private static final String TOKEN = "access_token";
    private static final String GRANT_TYPE = "grant_type";
    private static final String CLIENT_ID = "client_id";
    private static final String CLIENT_SECRET = "client_secret";
    private static final String CLIENT_NOT_FOUND_MESSAGE = "Client not found in Keycloak";

    // Store the clientId as variable and update it daily
    private String cachedClientId;

    // Called after the creation of Bean to retrieve client ID
    @PostConstruct
    public void init() {
        this.cachedClientId = retrieveClientId(retrieveComponentJwtToken(), clientId);
    }

    @Scheduled(fixedRate = 24 * 60 * 60 * 1000)
    public void refreshClientId() {
        this.cachedClientId = retrieveClientId(retrieveComponentJwtToken(),clientId);
    }

    public String getClientId() {
        return cachedClientId != null ? cachedClientId : retrieveClientId(retrieveComponentJwtToken(), clientId);
    }

    /**
     * Generate a JWT Token to access Keycloak resources
     *
     * @return Token
     */
    public String retrieveComponentJwtToken(){
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            String client = clientId;
            String secret = clientSecret;

            MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add(CLIENT_ID, client);
            map.add(CLIENT_SECRET, secret);
            map.add(GRANT_TYPE, "client_credentials");

            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, headers);
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    tokenUri,
                    HttpMethod.POST,
                    entity,
                    new ParameterizedTypeReference<>() {
                    }
            );

            if (response.getStatusCode().is2xxSuccessful()) {
                Map<String, Object> responseBody = response.getBody();
                if (responseBody == null || responseBody.get(TOKEN) == null) {
                    return null;
                }
                return responseBody.get(TOKEN).toString();
            }
            return null;
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            log.error("HTTP error during authenticating the client: Error: {}", e.getMessage());
            return null;
        } catch (RestClientException e) {
            log.error("Rest Client error during authenticating the client: Error: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Retrieve Client ID for a given Client
     *
     * @param token : JWT Token Value
     * @return String : Client ID
     */
    public String retrieveClientId(String token, String clientName){
        try {
            // Set Headers
            HttpHeaders headers = createAuthenticatedHeaders(token);

            HttpEntity<Object> entity = new HttpEntity<>(headers);

            // Retrieve Client ID from Keycloak
            String requestUri = adminUri.concat("/clients");
            ResponseEntity<List<ClientRepresentationDTO>> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<>() {}
            );

            // Parse response
            return Optional.of(response)
                    .filter(resp -> resp.getStatusCode().is2xxSuccessful())
                    .map(ResponseEntity::getBody)
                    .flatMap(body -> body.stream()
                            .filter(client -> client.getClientId().equals(clientName))
                            .map(ClientRepresentationDTO::getId)
                            .findFirst())
                .orElseThrow(() -> new DataRetrievalException(CLIENT_NOT_FOUND_MESSAGE));
        } catch (HttpServerErrorException | HttpClientErrorException e) {
            log.error("HTTP server error during retrieval of client ID: {}", e.getMessage(), e);
            throw new KeycloakException("HTTP server error during retrieval of client ID", e);
        } catch (RestClientException e) {
            log.error("Error during retrieval of client ID: {}", e.getMessage(), e);
            throw new KeycloakException("Error during retrieval of client ID", e);
        }
    }

    /**
     * Retrieve Group ID for a given Pilot Code
     *
     * @param token : JWT Token Value
     * @param pilot : Pilot Name
     * @return String : Client ID or Null if not found
     */
    public String retrievePilotCodeID(String token, String pilot){
        try {
            // Set Headers
            HttpHeaders headers = createAuthenticatedHeaders(token);

            HttpEntity<Void> entity = new HttpEntity<>(headers);

            // Retrieve Group ID from Keycloak
            String requestUri = adminUri.concat("/groups");
            ResponseEntity<List<GroupRepresentationDTO>> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<>() {}
            );

           // Parse response
           return Optional.of(response)
                   .filter(resp -> resp.getStatusCode().is2xxSuccessful())
                   .map(ResponseEntity::getBody)
                        .flatMap(body -> body.stream()
                           .filter(group -> group.getName().equalsIgnoreCase(pilot))
                           .map(GroupRepresentationDTO::getId)
                           .findFirst())
                  .orElse(null);
        } catch (RestClientException e) {
            log.error("Error during retrieval of group ID: {}", e.getMessage(), e);
            throw new DataRetrievalException("Unable to receive information about Pilots in the System");
        }
    }

    /*
     * Create the authentication Headers template
     */
    private HttpHeaders createAuthenticatedHeaders(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }
}
