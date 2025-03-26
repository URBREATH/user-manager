package gr.atc.urbreath.service;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import gr.atc.urbreath.dto.keycloak.GroupRepresentationDTO;
import static gr.atc.urbreath.exception.CustomExceptions.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.env.Environment;
import org.springframework.http.*;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import gr.atc.urbreath.dto.PilotDTO;
import gr.atc.urbreath.dto.keycloak.RoleRepresentationDTO;

@ExtendWith(MockitoExtension.class)
class AdminServiceTests {

  @Mock
  private RestTemplate restTemplate;

  @Mock
  private Environment env;

  @Mock
  private KeycloakSupportService keycloakSupportService;

  private AdminService adminService;

  private static final String MOCK_TOKEN = "mock-token";
  private static final String MOCK_ADMIN_URI = "http://mock-admin-uri";

  @BeforeEach
  void setup() {
    // Mock Environment
    when(env.getProperty("keycloak.realm")).thenReturn("urbreath");
    when(env.getProperty(eq("keycloak.excluded-roles.super-admin"), anyString())).thenReturn("default-roles-urbreath-system");
    when(env.getProperty(eq("keycloak.excluded-roles.admin"), anyString())).thenReturn("default-roles-urbreath-system");

    adminService = new AdminService(env, keycloakSupportService);

    // Mock Values of Properties
    ReflectionTestUtils.setField(adminService, "adminUri", MOCK_ADMIN_URI);
    ReflectionTestUtils.setField(adminService, "restTemplate", restTemplate);
    ReflectionTestUtils.setField(adminService, "rolePath", "/roles");
    ReflectionTestUtils.setField(adminService, "groupPath", "/groups");
  }

  @DisplayName("Retrieve all system roles: Success")
  @Test
  void givenValidJwt_whenRetrieveAllSystemRoles_thenReturnPilotRoles() {
    List<RoleRepresentationDTO> mockRoles =
        Arrays.asList(new RoleRepresentationDTO("1", "ADMIN", null, false, false, null, null),
            new RoleRepresentationDTO("2", "SUPER_ADMIN", null, false, false, null, null),
            new RoleRepresentationDTO("3", "default-roles-urbreath-system", null, false, false,null, null));

    ResponseEntity<List<RoleRepresentationDTO>> mockResponse =
        new ResponseEntity<>(mockRoles, HttpStatus.OK);

    when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(),
        any(ParameterizedTypeReference.class))).thenReturn(mockResponse);

    List<String> result = adminService.retrieveAllSystemRoles(MOCK_TOKEN, true);

    assertEquals(2, result.size());
    assertTrue(result.contains("ADMIN"));
    assertTrue(result.contains("SUPER_ADMIN"));
    assertFalse(result.contains("default-roles-modapto-system"));
  }

  @DisplayName("Retrieve all system roles: Empty Response - Fail")
  @Test
  void givenEmptyResponse_whenRetrieveAllSystemRoles_thenReturnEmptyList() {
    ResponseEntity<List<RoleRepresentationDTO>> mockResponse =
        new ResponseEntity<>(Collections.emptyList(), HttpStatus.OK);

    when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(),
        any(ParameterizedTypeReference.class))).thenReturn(mockResponse);

    List<String> result = adminService.retrieveAllSystemRoles(MOCK_TOKEN, true);

    assertTrue(result.isEmpty());
  }

  @DisplayName("Retrieve all system roles: Keycloak Exception - Fail")
  @Test
  void givenRestClientException_whenRetrieveAllSystemRoles_thenThrowKeycloakException() {
    when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(HttpEntity.class),
            any(ParameterizedTypeReference.class)))
            .thenThrow(new RestClientException("Connection error"));

    KeycloakException exception = assertThrows(KeycloakException.class, () ->
            adminService.retrieveAllSystemRoles(MOCK_TOKEN, true));
    assertNotNull(exception.getMessage());
  }

  @DisplayName("Retrieve all pilots: Success")
  @Test
  void givenValidJwt_whenRetrieveAllPilots_thenReturnPilots() {
    List<GroupRepresentationDTO> mockGroups = Arrays.asList(new GroupRepresentationDTO("1", "SEW", null, null),
        new GroupRepresentationDTO("2", "ATHENS", null, null));

    ResponseEntity<List<GroupRepresentationDTO>> mockResponse = new ResponseEntity<>(mockGroups, HttpStatus.OK);

    when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(),
        any(ParameterizedTypeReference.class))).thenReturn(mockResponse);

    List<String> result = adminService.retrieveAllPilots(MOCK_TOKEN);

    assertEquals(2, result.size());
    assertTrue(result.contains("SEW"));
    assertTrue(result.contains("ATHENS"));
  }

  @DisplayName("Retrieve all pilots: Keycloak Exception")
  @Test
  void givenRestClientException_whenRetrieveAllPilots_thenThrowKeycloakException() {
    when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(HttpEntity.class),
            any(ParameterizedTypeReference.class)))
            .thenThrow(new RestClientException("Timeout"));

    KeycloakException exception = assertThrows(KeycloakException.class, () ->
            adminService.retrieveAllPilots(MOCK_TOKEN));
    assertNotNull(exception.getMessage());
  }

  @DisplayName("Create a new Pilot: Success")
  @Test
  void givenValidJwtAndPilot_whenCreateNewPilot_thenReturnSuccess() {
    // Given
    String mockToken = "mock-jwt-token";
    PilotDTO pilotData = PilotDTO.builder().name("TEST_PILOT").build();
    String mockClientId = "test-client-id";

    // Mock URI
    String mainUri = MOCK_ADMIN_URI + "/groups";
    URI mockLocation = URI.create(mainUri + "/123");

    // Mock main group creation response
    ResponseEntity<Void> mockMainResponse = ResponseEntity
            .created(mockLocation)
            .build();

    when(restTemplate.exchange(
            eq(mainUri),
            eq(HttpMethod.POST),
            any(HttpEntity.class),
            eq(Void.class)
    )).thenReturn(mockMainResponse);

    // When
    boolean result = adminService.createPilot(mockToken, pilotData);

    // Then
    assertTrue(result);
    verify(restTemplate).exchange(
            eq(mainUri),
            eq(HttpMethod.POST),
            any(HttpEntity.class),
            eq(Void.class)
    );
  }

  @DisplayName("Create new Pilot : Main group creation failed")
  @Test
  void givenValidJwtAndPilot_whenMainGroupCreationFails_thenReturnFalse() {
    // Given
    String mockToken = "mock-jwt-token";
    PilotDTO pilotData = PilotDTO.builder()
            .name("TEST_PILOT")
            .build();

    String mainUri = MOCK_ADMIN_URI + "/groups";

    // Mock failed response for main group creation
    ResponseEntity<Void> mockMainResponse = ResponseEntity
            .status(HttpStatus.BAD_REQUEST)
            .build();

    when(restTemplate.exchange(
            eq(mainUri),
            eq(HttpMethod.POST),
            any(HttpEntity.class),
            eq(Void.class)
    )).thenReturn(mockMainResponse);

    // When
    boolean result = adminService.createPilot(mockToken, pilotData);

    // Then
    assertFalse(result);
    verify(restTemplate).exchange(
            eq(mainUri),
            eq(HttpMethod.POST),
            any(HttpEntity.class),
            eq(Void.class)
    );
    verify(restTemplate, never()).exchange(
            contains("/children"),
            eq(HttpMethod.POST),
            any(HttpEntity.class),
            eq(Void.class)
    );
  }

  @DisplayName("Create new Pilot : Pilot already exists")
  @Test
  void givenExistingPilot_whenCreatePilot_thenThrowResourceAlreadyExistsException() {
    PilotDTO pilotData = PilotDTO.builder().name("TEST_PILOT").build();
    // Simulate pilot exists
    when(keycloakSupportService.retrievePilotCodeID(MOCK_TOKEN, pilotData.getName())).thenReturn("existing-id");

    assertThrows(ResourceAlreadyExistsException.class, () ->
            adminService.createPilot(MOCK_TOKEN, pilotData));
    verify(restTemplate, never()).exchange(anyString(), any(HttpMethod.class), any(HttpEntity.class), eq(Void.class));
  }

  @DisplayName("Create new Pilot : KeycloakException")
  @Test
  void givenRestClientException_whenCreatePilot_thenThrowKeycloakException() {
    PilotDTO pilotData = PilotDTO.builder().name("TEST_PILOT").build();
    when(keycloakSupportService.retrievePilotCodeID(MOCK_TOKEN, pilotData.getName())).thenReturn(null);

    String requestUri = MOCK_ADMIN_URI + "/groups";
    when(restTemplate.exchange(eq(requestUri), eq(HttpMethod.POST), any(HttpEntity.class), eq(Void.class)))
            .thenThrow(new RestClientException("Service unavailable"));

    KeycloakException exception = assertThrows(KeycloakException.class, () ->
            adminService.createPilot(MOCK_TOKEN, pilotData));
    assertNotNull(exception.getMessage());
  }

  @DisplayName("Success: Pilot deleted successfully")
  @Test
  void givenValidPilot_whenDeletePilot_thenReturnTrue() {
    String pilotName = "TEST_PILOT";
    // Simulate pilot exists with an id
    when(keycloakSupportService.retrievePilotCodeID(MOCK_TOKEN, pilotName)).thenReturn("123");

    String requestUri = MOCK_ADMIN_URI + "/groups/123";
    ResponseEntity<Void> successResponse = new ResponseEntity<>(HttpStatus.OK);
    when(restTemplate.exchange(eq(requestUri), eq(HttpMethod.DELETE), any(HttpEntity.class), eq(Void.class)))
            .thenReturn(successResponse);

    boolean result = adminService.deletePilot(MOCK_TOKEN, pilotName);
    assertTrue(result);
    verify(restTemplate).exchange(eq(requestUri), eq(HttpMethod.DELETE), any(HttpEntity.class), eq(Void.class));
  }

  @DisplayName("Delete Pilot: Pilot not found")
  @Test
  void givenNonExistingPilot_whenDeletePilot_thenThrowDataRetrievalException() {
    String pilotName = "NON_EXISTENT";
    // Simulate pilot does not exist
    when(keycloakSupportService.retrievePilotCodeID(MOCK_TOKEN, pilotName)).thenReturn(null);

    assertThrows(DataRetrievalException.class, () ->
            adminService.deletePilot(MOCK_TOKEN, pilotName));
    verify(restTemplate, never()).exchange(anyString(), eq(HttpMethod.DELETE), any(HttpEntity.class), eq(Void.class));
  }


  @DisplayName("Update Pilot: Success")
  @Test
  void givenDifferentPilotName_whenUpdatePilot_thenReturnTrue() {
    String pilotName = "OLD_PILOT";
    PilotDTO updatedData = PilotDTO.builder().name("NEW_PILOT").build();

    // Stub retrieval of the existing pilot.
    List<GroupRepresentationDTO> groups = List.of(
            new GroupRepresentationDTO("123", "OLD_PILOT", null, null));
    ResponseEntity<List<GroupRepresentationDTO>> pilotResponse =
            new ResponseEntity<>(groups, HttpStatus.OK);
    when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(HttpEntity.class),
            any(ParameterizedTypeReference.class))).thenReturn(pilotResponse);

    String requestUri = MOCK_ADMIN_URI + "/groups/123";
    ResponseEntity<Void> successResponse = new ResponseEntity<>(HttpStatus.OK);
    when(restTemplate.exchange(eq(requestUri), eq(HttpMethod.PUT), any(HttpEntity.class), eq(Void.class)))
            .thenReturn(successResponse);

    boolean result = adminService.updatePilot(MOCK_TOKEN, pilotName, updatedData);
    assertTrue(result);
    // The update should change the group's name to NEW_PILOT.
    GroupRepresentationDTO updatedGroup = adminService.retrievePilot(MOCK_TOKEN, updatedData.getName());
    assertEquals("NEW_PILOT", updatedGroup.getName());
    verify(restTemplate).exchange(eq(requestUri), eq(HttpMethod.PUT), any(HttpEntity.class), eq(Void.class));
  }

  @DisplayName("Update Pilot: Error when pilot names are the same")
  @Test
  void givenSamePilotName_whenUpdatePilot_thenReturnTrueWithoutUpdate() {
    String pilotName = "SAME_PILOT";
    PilotDTO updatedData = PilotDTO.builder().name("SAME_PILOT").build();

    // Stub retrieval of the existing pilot.
    List<GroupRepresentationDTO> groups = List.of(
            new GroupRepresentationDTO("123", "SAME_PILOT", null, null));
    ResponseEntity<List<GroupRepresentationDTO>> pilotResponse =
            new ResponseEntity<>(groups, HttpStatus.OK);
    when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(HttpEntity.class),
            any(ParameterizedTypeReference.class))).thenReturn(pilotResponse);

    boolean result = adminService.updatePilot(MOCK_TOKEN, pilotName, updatedData);
    assertTrue(result);
    verify(restTemplate, never()).exchange(anyString(), eq(HttpMethod.PUT), any(HttpEntity.class), eq(Void.class));
  }


  @DisplayName("Retrieve Pilot: Success")
  @Test
  void givenExistingPilot_whenRetrievePilot_thenReturnGroupRepresentation() {
    String pilotName = "TEST_PILOT";
    List<GroupRepresentationDTO> groups = Arrays.asList(
            new GroupRepresentationDTO("1", "OTHER_PILOT", null, null),
            new GroupRepresentationDTO("2", "TEST_PILOT", null, null)
    );
    ResponseEntity<List<GroupRepresentationDTO>> pilotResponse =
            new ResponseEntity<>(groups, HttpStatus.OK);
    when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(HttpEntity.class),
            any(ParameterizedTypeReference.class))).thenReturn(pilotResponse);

    GroupRepresentationDTO result = adminService.retrievePilot(MOCK_TOKEN, pilotName);
    assertNotNull(result);
    assertEquals("TEST_PILOT", result.getName());
  }

  @DisplayName("Retrieve Pilot: Non-existing Pilot")
  @Test
  void givenNonExistingPilot_whenRetrievePilot_thenThrowDataRetrievalException() {
    String pilotName = "NON_EXISTENT";
    List<GroupRepresentationDTO> groups = Collections.singletonList(
            new GroupRepresentationDTO("1", "OTHER_PILOT", null, null)
    );
    ResponseEntity<List<GroupRepresentationDTO>> pilotResponse =
            new ResponseEntity<>(groups, HttpStatus.OK);
    when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(HttpEntity.class),
            any(ParameterizedTypeReference.class))).thenReturn(pilotResponse);

    assertThrows(DataRetrievalException.class, () ->
            adminService.retrievePilot(MOCK_TOKEN, pilotName));
  }
}

