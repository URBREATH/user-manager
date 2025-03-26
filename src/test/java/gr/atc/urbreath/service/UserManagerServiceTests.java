package gr.atc.urbreath.service;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import static org.mockito.Mockito.when;

import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import gr.atc.urbreath.dto.AuthenticationResponseDTO;
import gr.atc.urbreath.dto.CredentialsDTO;
import gr.atc.urbreath.dto.PasswordDTO;
import gr.atc.urbreath.dto.UserDTO;
import gr.atc.urbreath.dto.keycloak.ClientRepresentationDTO;
import gr.atc.urbreath.dto.keycloak.RoleRepresentationDTO;
import gr.atc.urbreath.dto.keycloak.UserRepresentationDTO;
import gr.atc.urbreath.exception.CustomExceptions;

@ExtendWith(MockitoExtension.class)
class UserManagerServiceTests {

  @Mock
  private RestTemplate restTemplate;

  @Mock
  private KeycloakSupportService keycloakSupportService;

  @Mock
  private IEmailService emailService;

  @InjectMocks
  private UserManagerService userManagerService;

  private CredentialsDTO credentials;
  private UserRepresentationDTO userRepresentation;
  private UserRepresentationDTO userRepresentationNotActivated;

  private static final String MOCK_TOKEN = "mock-token";
  private static final String MOCK_EMAIL = "mockemail@test.com";
  private static final String MOCK_PASSWORD = "@Mock123@";
  private static final String MOCK_ADMIN_URI = "http://mock-admin-uri";
  private static final String MOCK_TOKEN_URI = "http://mock-token-uri";
  private static final String MOCK_CLIENT_ID = "mock-client";
  private static final String MOCK_CLIENT_SECRET = "client-secret";

  // Strings commonly used
  private static final String TOKEN = "access_token";
  private static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";

  @BeforeEach
  void setup() {
    credentials = CredentialsDTO.builder().email(MOCK_EMAIL).password(MOCK_PASSWORD).build();

    userRepresentation = UserRepresentationDTO.builder().id("123").email(MOCK_EMAIL)
        .firstName("Test").lastName("User").enabled(true).username("TestUser").build();

    userRepresentationNotActivated = UserRepresentationDTO.builder().id("123").email(MOCK_EMAIL)
        .firstName("Test").lastName("User").enabled(false).username("TestUser").build();

    ReflectionTestUtils.setField(userManagerService, "adminUri", MOCK_ADMIN_URI);
    ReflectionTestUtils.setField(userManagerService, "tokenUri", MOCK_TOKEN_URI);
    ReflectionTestUtils.setField(userManagerService, "clientName", MOCK_CLIENT_ID);
    ReflectionTestUtils.setField(userManagerService, "clientSecret", MOCK_CLIENT_SECRET);
    ReflectionTestUtils.setField(userManagerService, "restTemplate", restTemplate);
    ReflectionTestUtils.setField(userManagerService, "userPath", "/userPath");
  }

  @AfterEach
  void tearDown() {
    Mockito.reset(restTemplate);
  }

  @DisplayName("Authenticate user: Success with credentials")
  @Test
  void givenCredentials_whenAuthenticate_thenReturnAuthenticationResponse() {
    // Given
    Map<String, Object> mockResponseBody = new HashMap<>();
    mockResponseBody.put(TOKEN, "mockAccessToken");
    mockResponseBody.put("expires_in", 1800);
    mockResponseBody.put("token_type", "JWT");
    mockResponseBody.put(GRANT_TYPE_REFRESH_TOKEN, "mockRefreshToken");
    mockResponseBody.put("refresh_expires_in", 1800);

    ResponseEntity<Map<String, Object>> mockResponse =
        new ResponseEntity<>(mockResponseBody, HttpStatus.OK);

    // When
    when(restTemplate.exchange(eq(MOCK_TOKEN_URI), eq(HttpMethod.POST), any(),
        any(ParameterizedTypeReference.class))).thenReturn(mockResponse);

    AuthenticationResponseDTO result = userManagerService.authenticate(credentials);

    // Then
    assertNotNull(result);
    assertEquals("mockAccessToken", result.getAccessToken());
    assertEquals(1800, result.getExpiresIn());
    assertEquals("JWT", result.getTokenType());
    assertEquals("mockRefreshToken", result.getRefreshToken());
    assertEquals(1800, result.getRefreshExpiresIn());
  }

  @DisplayName("Authenticate user: Failure with RestClientException")
  @Test
  void givenCredentials_whenRestClientException_thenReturnNull() {
    // Given
    when(restTemplate.exchange(eq(MOCK_TOKEN_URI), eq(HttpMethod.POST), any(),
        any(ParameterizedTypeReference.class)))
            .thenThrow(new RestClientException("Unable to connect"));

    // When - Then
    assertThrows(CustomExceptions.InvalidAuthenticationCredentialsException.class,
        () -> userManagerService.authenticate(credentials));
  }

  @DisplayName("Authenticate user: Success with refresh token")
  @Test
  void givenRefreshToken_whenAuthenticate_thenReturnAuthenticationResponse() {
    // Given
    String refreshToken = "mockRefreshToken";

    Map<String, Object> mockResponseBody = new HashMap<>();
    mockResponseBody.put(TOKEN, "mockAccessToken");
    mockResponseBody.put("expires_in", 1800);
    mockResponseBody.put("token_type", "JWT");
    mockResponseBody.put(GRANT_TYPE_REFRESH_TOKEN, "mockRefreshToken");
    mockResponseBody.put("refresh_expires_in", 1800);

    ResponseEntity<Map<String, Object>> mockResponse =
        new ResponseEntity<>(mockResponseBody, HttpStatus.OK);

    // When
    when(restTemplate.exchange(eq(MOCK_TOKEN_URI), eq(HttpMethod.POST), any(),
        any(ParameterizedTypeReference.class))).thenReturn(mockResponse);

    AuthenticationResponseDTO result = userManagerService.refreshToken(refreshToken);

    // Then
    assertNotNull(result);
    assertEquals("mockAccessToken", result.getAccessToken());
    assertEquals(1800, result.getExpiresIn());
    assertEquals("JWT", result.getTokenType());
    assertEquals("mockRefreshToken", result.getRefreshToken());
    assertEquals(1800, result.getRefreshExpiresIn());
  }

  @DisplayName("Retrieve user by email: Success")
  @Test
  void givenEmailAndJwt_whenRetrieveUserIdByEmail_thenReturnUserRepresentation() {
    // Given
    List<UserRepresentationDTO> mockResponseBody = List.of(userRepresentation);

    ResponseEntity<List<UserRepresentationDTO>> mockResponse =
        new ResponseEntity<>(mockResponseBody, HttpStatus.OK);

    String requestUri = MOCK_ADMIN_URI.concat("/users?email=").concat(MOCK_EMAIL);

    // When
    when(restTemplate.exchange(eq(requestUri), eq(HttpMethod.GET), any(HttpEntity.class),
        any(ParameterizedTypeReference.class))).thenReturn(mockResponse);

    // Call the service method
    UserRepresentationDTO result = userManagerService.retrieveUserByEmail(MOCK_EMAIL, MOCK_TOKEN);

    // Then
    assertNotNull(result);
    assertEquals(MOCK_EMAIL, result.getEmail());
    assertEquals("Test", result.getFirstName());
    assertEquals("User", result.getLastName());
  }

  @DisplayName("Retrieve user by email: HTTP Server Error")
  @Test
  void givenEmailAndJwt_whenHttpServerErrorException_thenReturnNull() {
    // Given
    String requestUri = MOCK_ADMIN_URI.concat("/users?email=").concat(MOCK_EMAIL);

    // Simulate HTTP server error
    when(restTemplate.exchange(eq(requestUri), eq(HttpMethod.GET), any(HttpEntity.class),
        any(ParameterizedTypeReference.class)))
            .thenThrow(new HttpServerErrorException(HttpStatus.INTERNAL_SERVER_ERROR,
                "Internal Server Error"));

    // When - Then
    assertThrows(CustomExceptions.KeycloakException.class,
        () -> userManagerService.retrieveUserByEmail(MOCK_EMAIL, MOCK_TOKEN));
  }

  @DisplayName("Create user: Success")
  @Test
  void givenUserDTO_whenCreateUser_thenReturnUserId() {
    // Given
    String expectedUserId = "123";
    String requestUri = MOCK_ADMIN_URI + "/userPath";

    when(keycloakSupportService.retrievePilotCodeID(anyString(), anyString())).thenReturn("TEST_PILOT");

    UserDTO userDTO =
        UserDTO.builder().email(MOCK_EMAIL).firstName("Test").lastName("User").pilotCode("TEST_PILOT").build();

    // Create response headers with Location
    HttpHeaders responseHeaders = new HttpHeaders();
    responseHeaders.setLocation(URI.create(MOCK_ADMIN_URI + "/userPath/" + expectedUserId));

    // Mock the response with exact parameter matching
    when(restTemplate.exchange(eq(requestUri), eq(HttpMethod.POST), any(HttpEntity.class),
        Mockito.<ParameterizedTypeReference<Map<String, Object>>>any()))
            .thenReturn(new ResponseEntity<>(new HashMap<>(), responseHeaders, HttpStatus.CREATED));

    // When
    String resultId = userManagerService.createUser(userDTO, MOCK_TOKEN);

    // Then
    assertNotNull(resultId, "Result ID should not be null");
    assertEquals(expectedUserId, resultId, "Result ID should match expected ID");
  }

  @DisplayName("Activate user: Success")
  @Test
  void givenValidActivationParams_whenActivateUser_thenReturnTrue() {
    // Add Attributes to user repsesentation
    Map<String, List<String>> tempMap = new HashMap<>();
    userRepresentationNotActivated.setAttributes(tempMap);
    userRepresentationNotActivated.getAttributes().put("activation_token", List.of("mock-token"));
    userRepresentationNotActivated.getAttributes().put("activation_expiry", List.of("random-time"));

    // Mock Keycloak Return of Token
    when(keycloakSupportService.retrieveComponentJwtToken()).thenReturn(MOCK_TOKEN);

    // Mock user retrieval
    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/userPath/123"), eq(HttpMethod.GET),
        any(HttpEntity.class), eq(UserRepresentationDTO.class)))
            .thenReturn(new ResponseEntity<>(userRepresentationNotActivated, HttpStatus.OK));

    // Mock user update
    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/userPath/123"), eq(HttpMethod.PUT),
        any(HttpEntity.class), eq(Object.class)))
            .thenReturn(new ResponseEntity<>(null, HttpStatus.NO_CONTENT));

    // Use spy service
    boolean result = userManagerService.activateUser("123", MOCK_TOKEN, "newPassword");

    assertTrue(result);
  }

  @DisplayName("Activate User: User Already Activated")
  @Test
  void givenAlreadyActivatedUser_whenActivateUser_thenReturnConflict() {
    // Add Attributes to user repsesentation
    Map<String, List<String>> tempMap = new HashMap<>();
    userRepresentation.setAttributes(tempMap);
    userRepresentation.getAttributes().put("activation_expiry", List.of("random-time"));

    // Mock Keycloak Return of Token
    when(keycloakSupportService.retrieveComponentJwtToken()).thenReturn(MOCK_TOKEN);

    // Mock user retrieval
    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/userPath/123"), eq(HttpMethod.GET),
        any(HttpEntity.class), eq(UserRepresentationDTO.class)))
            .thenReturn(new ResponseEntity<>(userRepresentation, HttpStatus.OK));

    // When - Then
    assertThrows(CustomExceptions.UserActivateStatusException.class,
        () -> userManagerService.activateUser("123", MOCK_TOKEN, "test-password"));
  }

  @DisplayName("Activate User: Missing activation token or activation expiry")
  @Test
  void givenActivatedUser_whenActivateUser_thenReturnErrorWithActivationProcess() {
    // Add Attributes to user repsesentation
    Map<String, List<String>> tempMap = new HashMap<>();
    userRepresentationNotActivated.setAttributes(tempMap);
    userRepresentationNotActivated.getAttributes().put("activation_expiry", List.of("random-time"));

    // Mock Keycloak Return of Token
    when(keycloakSupportService.retrieveComponentJwtToken()).thenReturn(MOCK_TOKEN);

    // Mock user retrieval
    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/userPath/123"), eq(HttpMethod.GET),
        any(HttpEntity.class), eq(UserRepresentationDTO.class)))
            .thenReturn(new ResponseEntity<>(userRepresentationNotActivated, HttpStatus.OK));

    // When - Then
    assertThrows(CustomExceptions.InvalidActivationAttributesException.class,
        () -> userManagerService.activateUser("123", MOCK_TOKEN, "test-password"));
  }


  @DisplayName("Update user: Success")
  @Test
  void givenUserInformation_whenUpdateUser_thenReturnTrue() {
    // Given
    UserDTO userDTO = new UserDTO();
    userDTO.setEmail(MOCK_EMAIL);
    userDTO.setFirstName("Updated");
    userDTO.setLastName("User");

    String userId = "123";

    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/userPath/" + userId), eq(HttpMethod.GET),
        any(HttpEntity.class), eq(UserRepresentationDTO.class)))
            .thenReturn(new ResponseEntity<>(userRepresentation, HttpStatus.OK));

    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/userPath/" + userId), eq(HttpMethod.PUT),
        any(HttpEntity.class), eq(Object.class)))
            .thenReturn(new ResponseEntity<>(null, HttpStatus.NO_CONTENT));

    // When
    boolean result = userManagerService.updateUser(userDTO, userId, MOCK_TOKEN);

    // Then
    assertTrue(result);
  }

  @DisplayName("Delete user: Success")
  @Test
  void givenUserId_whenDeleteUser_thenReturnTrue() {
    // Given
    String userId = "123";

    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/userPath/" + userId), eq(HttpMethod.DELETE),
        any(HttpEntity.class), eq(Void.class)))
            .thenReturn(new ResponseEntity<>(null, HttpStatus.NO_CONTENT));

    // When
    boolean result = userManagerService.deleteUser(userId, MOCK_TOKEN);

    // Then
    assertTrue(result);
  }

  @DisplayName("Change password: Success")
  @Test
  void givenNewPassword_whenChangePassword_thenReturnTrue() {
    // Given
    String userId = "123";
    String email = "test@email.com";
    PasswordDTO passwords = PasswordDTO.builder().currentPassword("@CurrentPass123@").newPassword("NewPassword123@").build();
    Map<String, Object> mockResponseBody = new HashMap<>();
    mockResponseBody.put(TOKEN, "mockAccessToken");
    mockResponseBody.put("expires_in", 1800);
    mockResponseBody.put("token_type", "JWT");
    mockResponseBody.put(GRANT_TYPE_REFRESH_TOKEN, "mockRefreshToken");
    mockResponseBody.put("refresh_expires_in", 1800);

    ResponseEntity<Map<String, Object>> mockResponse = new ResponseEntity<>(mockResponseBody, HttpStatus.OK);

    // Mock
    // Mock user retrievals
    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/userPath/" + userId), eq(HttpMethod.GET),
        any(HttpEntity.class), eq(UserRepresentationDTO.class)))
            .thenReturn(new ResponseEntity<>(userRepresentation, HttpStatus.OK));

    // Mock authenticate
    when(restTemplate.exchange(eq(MOCK_TOKEN_URI), eq(HttpMethod.POST), any(),
        any(ParameterizedTypeReference.class))).thenReturn(mockResponse);

    // Mock Password Reset
    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/userPath/" + userId + "/reset-password"),
        eq(HttpMethod.PUT), any(HttpEntity.class), eq(Object.class)))
            .thenReturn(new ResponseEntity<>(null, HttpStatus.NO_CONTENT));

    // When
    AuthenticationResponseDTO result = userManagerService.changePassword(passwords, userId, MOCK_TOKEN);

    // Then
    assertNotNull(result);
  }

  @DisplayName("Logout user: Success")
  @Test
  void givenUserId_whenLogoutUser_thenComplete() {
    // Given
    String userId = "123";

    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/userPath/" + userId + "/logout"),
        eq(HttpMethod.POST), any(HttpEntity.class), eq(Object.class)))
            .thenReturn(new ResponseEntity<>(null, HttpStatus.NO_CONTENT));

    // When & Then
    assertDoesNotThrow(() -> userManagerService.logoutUser(userId, MOCK_TOKEN));
  }

  @DisplayName("Assign realm roles: Success")
  @SuppressWarnings("unchecked")
  @Test
  void givenPilotRoleAndUserId_whenAssignRealmRoles_thenCompleteSuccessfully() {
    // Given
    String pilotRole = "admin";
    String userId = "123";

    RoleRepresentationDTO roleRepresentationDTO = new RoleRepresentationDTO();
    roleRepresentationDTO.setName(pilotRole);

    // Mock retrieveUserById
    when(restTemplate.exchange(
        eq(MOCK_ADMIN_URI + "/userPath/" + userId),
        eq(HttpMethod.GET),
        any(HttpEntity.class),
        eq(UserRepresentationDTO.class)
    )).thenReturn(new ResponseEntity<>(userRepresentation, HttpStatus.OK));

    // Mock deleteUserRealmRoles
    when(restTemplate.exchange(
        eq(MOCK_ADMIN_URI + "/userPath/" + userId + "/role-mappings/realm"),
        eq(HttpMethod.DELETE),
        any(HttpEntity.class),
        eq(Object.class)
    )).thenReturn(new ResponseEntity<>(HttpStatus.NO_CONTENT));

    // Mock findRoleRepresentationByUserRole
    when(restTemplate.exchange(
        eq(MOCK_ADMIN_URI + "/roles"),
        eq(HttpMethod.GET),
        any(HttpEntity.class),
        any(ParameterizedTypeReference.class)
    )).thenReturn(new ResponseEntity<>(List.of(roleRepresentationDTO), HttpStatus.OK));

    // Mock role assignment
    when(restTemplate.exchange(
        eq(MOCK_ADMIN_URI + "/userPath/" + userId + "/role-mappings/realm"),
        eq(HttpMethod.POST),
        any(HttpEntity.class),
        eq(Object.class)
    )).thenReturn(new ResponseEntity<>(HttpStatus.NO_CONTENT));

    // When
    boolean result = userManagerService.assignRealmRoles(pilotRole, userId, MOCK_TOKEN);

    // Then
    assertTrue(result);
  }

  @DisplayName("Assign realm management roles: Success")
  @SuppressWarnings("unchecked")
  @Test
  void givenPilotRoleAndUserId_whenAssignRealmManagementRoles_thenCompleteSuccessfully() {
    // Given
    String pilotRole = "ADMIN";
    String userId = "123";
    String clientId = "realm-management-client-id";

    RoleRepresentationDTO roleRepresentationDTO = new RoleRepresentationDTO();
    roleRepresentationDTO.setName("manage-users");

    ClientRepresentationDTO clientRepresentationDTO = new ClientRepresentationDTO();
    clientRepresentationDTO.setId(clientId);

    // Mock Keycloak Support service
    when(keycloakSupportService.retrieveClientId(anyString(), anyString())).thenReturn(clientId);

    // Mock retrieveUserById
    when(restTemplate.exchange(
        eq(MOCK_ADMIN_URI + "/userPath/" + userId),
        eq(HttpMethod.GET),
        any(HttpEntity.class),
        eq(UserRepresentationDTO.class)
    )).thenReturn(new ResponseEntity<>(userRepresentation, HttpStatus.OK));

    // Mock deleteUserRealmRoles
    when(restTemplate.exchange(
        eq(MOCK_ADMIN_URI + "/userPath/" + userId + "/role-mappings/clients/" + clientId),
        eq(HttpMethod.DELETE),
        any(HttpEntity.class),
        eq(Object.class)
    )).thenReturn(new ResponseEntity<>(HttpStatus.NO_CONTENT));

    Mockito.lenient()
        .when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/clients?clientId=realm-management"),
            eq(HttpMethod.GET), any(HttpEntity.class), any(ParameterizedTypeReference.class)))
        .thenReturn(new ResponseEntity<>(List.of(clientRepresentationDTO), HttpStatus.OK));

    Mockito.lenient()
        .when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/clients/" + clientId + "/roles"),
            eq(HttpMethod.GET), any(HttpEntity.class), any(ParameterizedTypeReference.class)))
        .thenReturn(new ResponseEntity<>(List.of(roleRepresentationDTO), HttpStatus.OK));

    Mockito.lenient()
        .when(restTemplate.exchange(
            eq(MOCK_ADMIN_URI + "/userPath/" + userId + "/role-mappings/clients/" + clientId),
            eq(HttpMethod.POST), any(HttpEntity.class), eq(Object.class)))
        .thenReturn(new ResponseEntity<>(null, HttpStatus.NO_CONTENT));

    // When - Then
   assertDoesNotThrow(() -> userManagerService.assignRealmManagementRoles(pilotRole, userId, MOCK_TOKEN));
  }

  @DisplayName("Fetch user by email: Success")
  @Test
  void givenEmailAndJwt_whenFetchUserByEmail_thenReturnUserRepresentation() {
    // Given
    List<UserRepresentationDTO> mockResponseBody = List.of(userRepresentation);

    // Mock the REST call
    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/users?email=" + MOCK_EMAIL),
        eq(HttpMethod.GET), any(HttpEntity.class),
        Mockito.<ParameterizedTypeReference<List<UserRepresentationDTO>>>any()))
            .thenReturn(new ResponseEntity<>(mockResponseBody, HttpStatus.OK));

    // When
    UserRepresentationDTO result = userManagerService.retrieveUserByEmail(MOCK_EMAIL, MOCK_TOKEN);

    // Then
    assertNotNull(result);
    assertEquals(MOCK_EMAIL, result.getEmail());
    assertEquals("Test", result.getFirstName());
    assertEquals("User", result.getLastName());
  }

  @DisplayName("Fetch user by ID: Success")
  @Test
  void givenUserIdAndJwt_whenFetchUserById_thenReturnUserRepresentation() {
    // Given
    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/userPath/" + "123"), eq(HttpMethod.GET),
        any(HttpEntity.class), eq(UserRepresentationDTO.class)))
            .thenReturn(new ResponseEntity<>(userRepresentation, HttpStatus.OK));

    // When
    UserRepresentationDTO result = userManagerService.retrieveUserById("123", MOCK_TOKEN);

    // Then
    assertNotNull(result);
    assertEquals(MOCK_EMAIL, result.getEmail());
    assertEquals("Test", result.getFirstName());
    assertEquals("User", result.getLastName());
  }

  @DisplayName("Fetch users: Success")
  @SuppressWarnings("unchecked")
  @Test
  void givenJwt_whenFetchUsers_thenReturnListOfUsers() {
    // Given
    List<UserRepresentationDTO> mockResponseBody = List.of(userRepresentation);

    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/userPath"), eq(HttpMethod.GET),
        any(HttpEntity.class), any(ParameterizedTypeReference.class)))
            .thenReturn(new ResponseEntity<>(mockResponseBody, HttpStatus.OK));

    // When
    List<UserDTO> result = userManagerService.retrieveUsers(MOCK_TOKEN, "ALL");

    // Then
    assertNotNull(result);
    assertFalse(result.isEmpty());
    assertEquals(1, result.size());
    assertEquals(MOCK_EMAIL, result.getFirst().getEmail());
    assertEquals("Test", result.getFirst().getFirstName());
  }


  @DisplayName("Forgot Password: User Not Found")
  @Test
  void givenInvalidEmail_whenForgotPassword_thenThrowDataRetrievalException() {
    // Given
    String email = "nonexistent@test.com";

    // Mock Keycloak Return of Token
    when(keycloakSupportService.retrieveComponentJwtToken()).thenReturn(MOCK_TOKEN);

    // Mock user retrieval by email returning empty list
    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/users?email=" + email), eq(HttpMethod.GET),
        any(HttpEntity.class), any(ParameterizedTypeReference.class)))
            .thenReturn(new ResponseEntity<>(Collections.emptyList(), HttpStatus.OK));

    // When & Then
    assertThrows(CustomExceptions.DataRetrievalException.class,
        () -> userManagerService.forgotPassword(email));
  }

  @DisplayName("Forgot Password: User Not Activated")
  @Test
  void givenNonActivatedUserEmail_whenForgotPassword_thenThrowUserActivateStatusException() {
    // Given
    String email = "inactive@test.com";

    // Mock Keycloak Return of Token
    when(keycloakSupportService.retrieveComponentJwtToken()).thenReturn(MOCK_TOKEN);

    // Mock user retrieval by email returning inactive user
    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/users?email=" + email), eq(HttpMethod.GET),
        any(HttpEntity.class), any(ParameterizedTypeReference.class))).thenReturn(
            new ResponseEntity<>(List.of(userRepresentationNotActivated), HttpStatus.OK));

    // When & Then
    assertThrows(CustomExceptions.UserActivateStatusException.class,
        () -> userManagerService.forgotPassword(email));
  }

  @DisplayName("Reset Password: Success")
  @Test
  void givenValidResetTokenAndPassword_whenResetPassword_thenReturnTrue() {
    // Given
    String userId = "123";
    String resetToken = "valid-reset-token";
    String newPassword = "NewPassword123@";
    Map<String, List<String>> attributes = new HashMap<>();
    attributes.put("reset_token", List.of(resetToken));
    userRepresentation.setAttributes(attributes);

    // Mock Keycloak Return of Token
    when(keycloakSupportService.retrieveComponentJwtToken()).thenReturn(MOCK_TOKEN);

    // Mock user retrieval
    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/userPath/" + userId), eq(HttpMethod.GET),
        any(HttpEntity.class), eq(UserRepresentationDTO.class)))
            .thenReturn(new ResponseEntity<>(userRepresentation, HttpStatus.OK));

    // Mock user update
    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/userPath/" + userId), eq(HttpMethod.PUT),
        any(HttpEntity.class), eq(Object.class)))
            .thenReturn(new ResponseEntity<>(null, HttpStatus.NO_CONTENT));

    // When
    boolean result = userManagerService.resetPassword(userId, resetToken, newPassword);

    // Then
    assertTrue(result);
  }

  @DisplayName("Reset Password: Invalid Reset Token")
  @Test
  void givenInvalidResetToken_whenResetPassword_thenThrowInvalidResetTokenAttributesException() {
    // Given
    String userId = "123";
    String invalidResetToken = "invalid-token";
    String newPassword = "NewPassword123@";
    Map<String, List<String>> attributes = new HashMap<>();
    attributes.put("reset_token", List.of("different-token"));
    userRepresentation.setAttributes(attributes);

    // Mock Keycloak Return of Token
    when(keycloakSupportService.retrieveComponentJwtToken()).thenReturn(MOCK_TOKEN);

    // Mock user retrieval
    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/userPath/" + userId), eq(HttpMethod.GET),
        any(HttpEntity.class), eq(UserRepresentationDTO.class)))
            .thenReturn(new ResponseEntity<>(userRepresentation, HttpStatus.OK));

    // When & Then
    assertThrows(CustomExceptions.InvalidResetTokenAttributesException.class,
        () -> userManagerService.resetPassword(userId, invalidResetToken, newPassword));
  }

  @DisplayName("Reset Password: User Not Activated")
  @Test
  void givenNonActivatedUser_whenResetPassword_thenThrowUserActivateStatusException() {
    // Given
    String userId = "123";
    String resetToken = "valid-reset-token";
    String newPassword = "NewPassword123@";

    // Mock Keycloak Return of Token
    when(keycloakSupportService.retrieveComponentJwtToken()).thenReturn(MOCK_TOKEN);

    // Mock user retrieval returning inactive user
    when(restTemplate.exchange(eq(MOCK_ADMIN_URI + "/userPath/" + userId), eq(HttpMethod.GET),
        any(HttpEntity.class), eq(UserRepresentationDTO.class)))
            .thenReturn(new ResponseEntity<>(userRepresentationNotActivated, HttpStatus.OK));

    // When & Then
    assertThrows(CustomExceptions.UserActivateStatusException.class,
        () -> userManagerService.resetPassword(userId, resetToken, newPassword));
  }
}

