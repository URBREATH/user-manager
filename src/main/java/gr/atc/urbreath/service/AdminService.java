package gr.atc.urbreath.service;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import gr.atc.urbreath.dto.PilotDTO;
import gr.atc.urbreath.dto.keycloak.GroupRepresentationDTO;
import gr.atc.urbreath.dto.keycloak.RoleRepresentationDTO;
import gr.atc.urbreath.exception.CustomExceptions;
import gr.atc.urbreath.exception.CustomExceptions.DataRetrievalException;
import gr.atc.urbreath.exception.CustomExceptions.KeycloakException;
import gr.atc.urbreath.exception.CustomExceptions.ResourceAlreadyExistsException;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class AdminService implements IAdminService {
    @Value("${keycloak.admin.uri}")
    private String adminUri;
    
    @Value("${keycloak.api.role-path:/roles}")
    private String rolePath;

    @Value("${keycloak.api.group-path:/groups}")
    private String groupPath;

    private final RestTemplate restTemplate = new RestTemplate();
    private final KeycloakSupportService keycloakSupportService;


    private static final String ERROR_MESSAGE_FIELD = "errorMessage";
    private static final String GROUP_NOT_FOUND_MESSAGE = "Pilot Code not found in Keycloak";

    // Realm Default Roles
    private final List<String> superAdminExcludedRoles;
    private final List<String> adminExcludedRoles;

    public AdminService(Environment env, KeycloakSupportService keycloakSupportService){
        this.keycloakSupportService = keycloakSupportService;

        // Set the excluded roles
        this.superAdminExcludedRoles = Arrays.stream(env.getProperty("keycloak.excluded-roles.super-admin", "")
                        .replace("#{keycloak.realm}", Objects.requireNonNull(env.getProperty("keycloak.realm")))
                        .split(","))
                .map(String::trim)
                .collect(Collectors.toList());

        this.adminExcludedRoles = Arrays.stream(env.getProperty("keycloak.excluded-roles.admin", "")
                        .replace("#{keycloak.realm}", Objects.requireNonNull(env.getProperty("keycloak.realm")))
                        .split(","))
                .map(String::trim)
                .collect(Collectors.toList());
    }

    /**
     * Retrieve all System Roles from Keycloak
     *
     * @param token : JWT Token value
     * @return List<String> : System Roles
     */
    @Override
    public List<String> retrieveAllSystemRoles(String token, boolean isSuperAdmin) {
        try {
            // Set Headers
            HttpHeaders headers = createAuthenticatedHeaders(token);

            HttpEntity<Void> entity = new HttpEntity<>(headers);

            String requestUri = adminUri.concat(rolePath);
            ResponseEntity<List<RoleRepresentationDTO>> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.GET,
                    entity,
                    new ParameterizedTypeReference<>() {}
            );

            log.info("Admin List: {}", adminExcludedRoles);
            log.info("S Admin List: {}", superAdminExcludedRoles);
            // Select the appropriate list according to whether pilot code was inserted or not
            List<String> excludedList = isSuperAdmin ? superAdminExcludedRoles : adminExcludedRoles;
            
            // Parse response
            return Optional.of(response)
                    .filter(resp -> resp.getStatusCode().is2xxSuccessful())
                    .map(ResponseEntity::getBody)
                    .map(body -> body.stream()
                            .map(RoleRepresentationDTO::getName)
                            .filter(name -> !excludedList.contains(name))
                            .toList())
                    .orElse(Collections.emptyList());
        } catch (RestClientException e) {
            log.error("Error during retrieval of user roles: {}", e.getMessage(), e);
            throw new KeycloakException("Error during retrieval of user roles", e);
        }
    }

    /**
     * Retrieve all Pilots from Keycloak
     *
     * @param token : JWT Token value
     * @return List<String> : Pilot Names
     */
    @Override
    public List<String> retrieveAllPilots(String token) {
        try {
            // Set Headers
            HttpHeaders headers = createAuthenticatedHeaders(token);

            HttpEntity<Void> entity = new HttpEntity<>(headers);

            String requestUri = adminUri.concat(groupPath);
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
              .map(body -> body.stream()
              .map(GroupRepresentationDTO::getName)
                      .toList())
              .orElse(Collections.emptyList());
        } catch (RestClientException e) {
            log.error("Error during retrieval of pilot codes: {}", e.getMessage(), e);
            throw new KeycloakException("Error during retrieval of pilot codes", e);
        }
    }


    /**
     * Create a new Pilot (Group) in Keycloak
     *
     * @param token  : JWT Token Value
     * @param pilotData   : Information for Group Creation
     * @return True on success, False on error
     */
    @Override
    public boolean createPilot(String token, PilotDTO pilotData) {

        // Validate that Pilot Code does not exist in Keycloak
        String pilotId = keycloakSupportService.retrievePilotCodeID(token, pilotData.getName());
        if (pilotId != null)
            throw new ResourceAlreadyExistsException("Specified Pilot Code already exists in Keycloak");

        // Set Headers
        HttpHeaders headers = createAuthenticatedHeaders(token);

        // Formulate the Group
        GroupRepresentationDTO group = GroupRepresentationDTO.builder()
                .name(pilotData.getName().toUpperCase())
                .build();

        HttpEntity<GroupRepresentationDTO> entity = new HttpEntity<>(group, headers);

        // Create the URI and make the POST request
        String requestUri = adminUri.concat(groupPath);
        try{
            ResponseEntity<Void> mainGroupResponse = restTemplate.exchange(
                    requestUri,
                    HttpMethod.POST,
                    entity,
                    Void.class
            );

          return mainGroupResponse.getStatusCode().is2xxSuccessful();
        } catch (RestClientException e) {
            log.error("Error during creating a new Pilot in Keycloak: {}", e.getMessage(), e);
            throw new KeycloakException("Error during creating a new Pilot in Keycloak", e);
        }
    }

    /**
     * Delete pilot from Keycloak (if exists)
     *
     * @param token : JWT Token Value
     * @param pilotName  : Name of Pilot
     * @return True on success, False on error
     */
    @Override
    public boolean deletePilot(String token, String pilotName) {
        try {
            // Retrieve the specified pilot
            String pilotId = keycloakSupportService.retrievePilotCodeID(token, pilotName);
            if (pilotId == null)
                throw new DataRetrievalException(GROUP_NOT_FOUND_MESSAGE);

            // Set Headers
            HttpHeaders headers = createAuthenticatedHeaders(token);

            HttpEntity<Void> entity = new HttpEntity<>(headers);

            String requestUri = adminUri.concat(groupPath).concat("/").concat(pilotId);
            ResponseEntity<Void> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.DELETE,
                    entity,
                    Void.class
            );

            // Parse response
            return response.getStatusCode().is2xxSuccessful();
        } catch (HttpClientErrorException e){
            Map<String, Object> responseBody = e.getResponseBodyAs(new ParameterizedTypeReference<>() {});
            if (responseBody != null && responseBody.containsKey(ERROR_MESSAGE_FIELD)) {
                throw new DataRetrievalException(responseBody.get(ERROR_MESSAGE_FIELD).toString());
            }
            throw new DataRetrievalException("Pilot with this ID not found in Keycloak");
        } catch (RestClientException e) {
            log.error("Error during deleting specified pilot: {}", e.getMessage(), e);
            throw new KeycloakException("Error during deleting specified pilot", e);
        }
    }

    /**
     * Update pilot information from Keycloak (if exists)
     *
     * @param token : JWT Token Value
     * @param pilotName  : Name of Pilot
     * @param pilotData  : Updated Pilot Data
     * @return True on success, False on error
     */
    @Override
    public boolean updatePilot(String token, String pilotName, PilotDTO pilotData) {
        try{
            GroupRepresentationDTO existingPilot = retrievePilot(token, pilotName);

            // Update the name or return true if the name is the same
            if (existingPilot.getName().equalsIgnoreCase(pilotData.getName()))
                return true;

            existingPilot.setName(pilotData.getName());

            // Set Headers
            HttpHeaders headers = createAuthenticatedHeaders(token);

            HttpEntity<GroupRepresentationDTO> entity = new HttpEntity<>(existingPilot, headers);

            String requestUri = adminUri.concat(groupPath).concat("/").concat(existingPilot.getId());
            ResponseEntity<Void> response = restTemplate.exchange(
                    requestUri,
                    HttpMethod.PUT,
                    entity,
                    Void.class
            );

            // Parse response
            return response.getStatusCode().is2xxSuccessful();
        } catch (HttpClientErrorException e){
            Map<String, Object> responseBody = e.getResponseBodyAs(new ParameterizedTypeReference<>() {});
            if (responseBody != null && responseBody.containsKey(ERROR_MESSAGE_FIELD)) {
                throw new DataRetrievalException(responseBody.get(ERROR_MESSAGE_FIELD).toString());
            }
            throw new DataRetrievalException("Pilot with this ID not found in Keycloak");
        } catch (RestClientException e) {
            log.error("Error during deleting specified pilot: {}", e.getMessage(), e);
            throw new KeycloakException("Error during deleting specified pilot", e);
        }
    }


    /**
     * Retrieve pilot information from Keycloak (if exists)
     *
     * @param token : JWT Token Value
     * @param pilotName  : Name of Pilot
     * @return GroupRepresentationDTO
     */
    @Override
    public GroupRepresentationDTO retrievePilot(String token, String pilotName){
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
                            .filter(group -> group.getName().equalsIgnoreCase(pilotName))
                            .findFirst())
                    .orElseThrow(() -> new DataRetrievalException(GROUP_NOT_FOUND_MESSAGE));
    } catch (HttpServerErrorException | HttpClientErrorException e) {
        log.error("HTTP server error during retrieval of group ID: {}", e.getMessage(), e);
        throw new CustomExceptions.KeycloakException("HTTP server error during retrieval of Pilot ID", e);
    } catch (RestClientException e) {
        log.error("Error during retrieval of group ID: {}", e.getMessage(), e);
        throw new CustomExceptions.KeycloakException("Error during retrieval of client ID", e);
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
