package gr.atc.urbreath.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.hamcrest.CoreMatchers.is;

import gr.atc.urbreath.exception.CustomExceptions;
import gr.atc.urbreath.service.IUserManagerService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import gr.atc.urbreath.dto.AuthenticationResponseDTO;
import gr.atc.urbreath.dto.CredentialsDTO;
import gr.atc.urbreath.dto.PasswordDTO;
import gr.atc.urbreath.dto.UserDTO;
import gr.atc.urbreath.dto.keycloak.UserRepresentationDTO;
import gr.atc.urbreath.enums.PilotRole;
import gr.atc.urbreath.service.KeycloakSupportService;

@SpringBootTest
@AutoConfigureMockMvc
@EnableMethodSecurity(prePostEnabled = true)
class UserManagerControllerTests {

  @MockitoBean
  private JwtDecoder jwtDecoder;

  @Autowired
  private MockMvc mockMvc;

  @MockitoBean
  private KeycloakSupportService keycloakSupportService;

  @MockitoBean
  private IUserManagerService userManagerService;

  @Autowired
  private ObjectMapper objectMapper;

  private static CredentialsDTO credentials;
  private static AuthenticationResponseDTO authenticationResponse;
  private static UserDTO user;
  private static Jwt jwt;

  @BeforeAll
  @SuppressWarnings("unused")
  static void setup() {
    credentials = CredentialsDTO.builder().email("test@test.com").password("TestPass123@").build();

    authenticationResponse =
        AuthenticationResponseDTO.builder().accessToken("accessToken").expiresIn(1800)
            .tokenType("JWT").refreshToken("refreshToken").refreshExpiresIn(1800).build();

    user = UserDTO.builder().userId("12345").email("test@test.com").firstName("Test")
        .lastName("Test").username("UserTest").password("TestPass123@").pilotCode("ATHENS")
        .pilotRole(PilotRole.ADMIN).build();

    String tokenValue = "mock.jwt.token";
    Map<String, Object> claims = new HashMap<>();
    claims.put("realm_access", Map.of("roles", List.of("SUPER_ADMIN")));
    claims.put("resource_access", Map.of("modapto", Map.of("roles", List.of("SUPER_ADMIN"))));
    claims.put("sub", "user");
    claims.put("pilot_code", "ALL");
    claims.put("user_role", "SUPER_ADMIN");
    claims.put("pilot_role", "SUPER_ADMIN");

    jwt = Jwt.withTokenValue(tokenValue).headers(header -> header.put("alg", "HS256"))
        .claims(claim -> claim.putAll(claims)).build();

  }

  @WithMockUser(roles = "SUPER_ADMIN")
  @DisplayName("Authenticate User: Success")
  @Test
  void givenUserCredentials_whenAuthenticate_thenReturnAccessTokens() throws Exception {
    // Given
    given(userManagerService.authenticate(credentials)).willReturn(authenticationResponse);

    // When
    ResultActions response =
        mockMvc.perform(post("/api/users/authenticate").contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(credentials)));

    // Then
    response.andExpect(status().isOk()).andExpect(jsonPath("$.success", is(true)))
        .andExpect(jsonPath("$.message", is("Authentication token generated successfully")))
        .andExpect(jsonPath("$.data.accessToken", is(authenticationResponse.getAccessToken())));

  }

  @DisplayName("Refresh Token: Success")
  @Test
  void givenRefreshToken_whenRefreshToken_thenReturnNewAccessTokens() throws Exception {
    // Given
    given(userManagerService.refreshToken("test_token")).willReturn(authenticationResponse);

    // When
    ResultActions response = mockMvc.perform(post("/api/users/refresh-token")
        .contentType(MediaType.APPLICATION_JSON).param("token", "test_token"));


    // Then
    response.andExpect(status().isOk()).andExpect(jsonPath("$.success", is(true)))
        .andExpect(jsonPath("$.message", is("Authentication token generated successfully")))
        .andExpect(jsonPath("$.data.accessToken", is(authenticationResponse.getAccessToken())));
  }

  @DisplayName("Authenticate User: Invalid Format of Credentials")
  @Test
  void givenInvalidUserCredentials_whenAuthenticate_thenReturnBadRequest() throws Exception {

    // When
    ResultActions response =
        mockMvc.perform(post("/api/users/authenticate").contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(new CredentialsDTO("email", "password"))));

    // Then
    response.andExpect(status().isBadRequest()).andExpect(jsonPath("$.success", is(false)))
        .andExpect(jsonPath("$.message", is("Validation failed")));
  }


  @DisplayName("Authenticate User: Wrong Credentias")
  @Test
  void givenWrongCredentials_whenAuthenticate_thenReturnUnauthorized() throws Exception {
    // Given
    given(userManagerService.authenticate(credentials)).willThrow(CustomExceptions.InvalidAuthenticationCredentialsException.class);

    // When
    ResultActions response =
        mockMvc.perform(post("/api/users/authenticate").contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(credentials)));

    // Then
    response.andExpect(status().isUnauthorized()).andExpect(jsonPath("$.success", is(false)))
        .andExpect(jsonPath("$.message", is("Invalid authorization credentials provided.")));
  }

  @DisplayName("No credentials given: Failure")
  @Test
  void givenNoInput_whenAuthenticate_thenReturnBadRequest() throws Exception {

    // When
    ResultActions response =
        mockMvc.perform(post("/api/users/authenticate").contentType(MediaType.APPLICATION_JSON));

    // Then
    response.andExpect(status().isBadRequest()).andExpect(jsonPath("$.success", is(false)));
  }

  @DisplayName("No token given: Failure")
  @Test
  void givenNoInput_whenRefreshToken_thenReturnBadRequest() throws Exception {

    // When
    ResultActions response =
        mockMvc.perform(post("/api/users/refresh-token").contentType(MediaType.APPLICATION_JSON));

    // Then
    response.andExpect(status().isBadRequest()).andExpect(jsonPath("$.success", is(false)))
        .andExpect(
            jsonPath("$.message", is("Invalid / No input was given for requested resource")));
  }

  @DisplayName("Logout User: Success")
  @Test
  void givenValidJwt_whenLogout_thenReturnSuccessMessage() throws Exception {
    // Given
    CompletableFuture<Void> completableFuture = new CompletableFuture<>();
    completableFuture.complete(null);

    // Mock JWT authentication
    JwtAuthenticationToken jwtAuthenticationToken =
        new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
    SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

    // When
    ResultActions response =
        mockMvc.perform(post("/api/users/logout").contentType(MediaType.APPLICATION_JSON));

    // Then
    response.andExpect(status().isOk()).andExpect(jsonPath("$.success", is(true)))
        .andExpect(jsonPath("$.message", is("User logged out successfully")));
  }

  @DisplayName("Create User: Success")
  @Test
  void givenValidUser_whenCreateUser_thenReturnSuccess() throws Exception {
    // Given
    CompletableFuture<Void> completableFuture = new CompletableFuture<>();
    completableFuture.complete(null);
    given(userManagerService.retrieveUserByEmail(anyString(), anyString())).willReturn(null);
    given(userManagerService.createUser(any(UserDTO.class), anyString())).willReturn("12345");

    // Mock JWT authentication
    JwtAuthenticationToken jwtAuthenticationToken =
        new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
    SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

    // When
    ResultActions response = mockMvc.perform(post("/api/users/create")
        .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(user)));

    // Then
    response.andExpect(status().isCreated()).andExpect(jsonPath("$.success", is(true)))
        .andExpect(jsonPath("$.message", is("User created successfully")));
  }

  @DisplayName("Create User: Failed - Missing Values")
  @Test
  void givenIncompleteUser_whenCreateUser_thenReturnBadRequest() throws Exception {
    // Given
    UserDTO userDTO = new UserDTO();

    // Mock JWT authentication
    JwtAuthenticationToken jwtAuthenticationToken =
        new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
    SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

    // When
    ResultActions response = mockMvc.perform(post("/api/users/create")
        .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(userDTO)));

    // Then
    response.andExpect(status().isBadRequest()).andExpect(jsonPath("$.success", is(false)))
            .andExpect(jsonPath("$.message", is("Validation failed")))
            .andExpect(jsonPath("$.errors", is("Input data are missing or are empty")));
  }

  @DisplayName("Create User: User Already Exists")
  @Test
  void givenExistingUser_whenCreateUser_thenReturnExpectationFailed() throws Exception {
    // Given
    UserRepresentationDTO userRepr = UserRepresentationDTO.toUserRepresentationDTO(user, null);
    given(userManagerService.retrieveUserByEmail(anyString(), anyString())).willReturn(userRepr);

    // Mock JWT authentication
    JwtAuthenticationToken jwtAuthenticationToken =
        new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
    SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

    // When
    ResultActions response = mockMvc.perform(post("/api/users/create")
        .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(user)));

    // Then
    response.andExpect(status().isConflict()).andExpect(jsonPath("$.success", is(false))).andExpect(
        jsonPath("$.message", is("User with the given email already exists in Keycloak")));
  }

  @DisplayName("Update User: Success")
  @Test
  void givenValidUser_whenUpdateUser_thenReturnSuccess() throws Exception {
    // Given
    given(userManagerService.updateUser(any(UserDTO.class), anyString(), anyString()))
        .willReturn(true);
    given(userManagerService.retrieveUserById(anyString(), anyString()))
        .willReturn(UserRepresentationDTO.toUserRepresentationDTO(user, null));

    // Mock JWT authentication
    JwtAuthenticationToken jwtAuthenticationToken =
        new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
    SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

    // When
    ResultActions response =
        mockMvc.perform(put("/api/users/update").contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(user)).param("userId", "12345"));

    // Then
    response.andExpect(status().isOk()).andExpect(jsonPath("$.success", is(true)))
        .andExpect(jsonPath("$.message", is("User updated successfully")));
  }

  @DisplayName("Update User: Forbidden for Non-Admin Users updating other users")
  @Test
  void givenSimpleUser_whenUpdateOtherUserOutsidePilot_thenReturnForbidden() throws Exception {
    // Given
    Jwt mockToken = createMockJwtToken("ADMIN", "MADRID");
    given(userManagerService.retrieveUserById(anyString(), anyString()))
        .willReturn(UserRepresentationDTO.toUserRepresentationDTO(user, null));

    // Mock JWT authentication
    JwtAuthenticationToken jwtAuthenticationToken =
        new JwtAuthenticationToken(mockToken, List.of(new SimpleGrantedAuthority("ROLE_USER")));
    SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

    // When
    ResultActions response =
        mockMvc.perform(put("/api/users/update").contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(user)).param("userId", user.getUserId()));

    // Then
    response.andExpect(status().isForbidden()).andExpect(jsonPath("$.success", is(false)))
        .andExpect(jsonPath("$.message",
            is("User of type 'ADMIN' can only update user's inside their organization")));
  }

  @DisplayName("Update User: Forbidden for Admin Users updating  users outside their organization")
  @Test
  void givenAdminUser_whenUpdateOtherUserInAnotherPilot_thenReturnForbidden() throws Exception {
    // Given
    Jwt mockToken = createMockJwtToken("ADMIN", "MADRID");
    given(userManagerService.retrieveUserById(anyString(), anyString()))
        .willReturn(UserRepresentationDTO.toUserRepresentationDTO(user, null));

    // Mock JWT authentication
    JwtAuthenticationToken jwtAuthenticationToken =
        new JwtAuthenticationToken(mockToken, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
    SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

    // When
    ResultActions response =
        mockMvc.perform(put("/api/users/update").contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(user)).param("userId", user.getUserId()));

    // Then
    response.andExpect(status().isForbidden()).andExpect(jsonPath("$.success", is(false)))
        .andExpect(jsonPath("$.message",
            is("User of type 'ADMIN' can only update user's inside their organization")));
  }

  @DisplayName("Update User: Failure")
  @Test
  void givenValidUser_whenUpdateUserFails_thenReturnServerError() throws Exception {
    // Given
    given(userManagerService.updateUser(any(UserDTO.class), anyString(), anyString()))
        .willReturn(false);
    given(userManagerService.retrieveUserById(anyString(), anyString()))
        .willReturn(UserRepresentationDTO.toUserRepresentationDTO(user, null));

    // Mock JWT authentication
    JwtAuthenticationToken jwtAuthenticationToken =
        new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_USER")));
    SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

    // When
    ResultActions response =
        mockMvc.perform(put("/api/users/update").contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(user)).param("userId", "12345"));

    // Then
    response.andExpect(status().isInternalServerError()).andExpect(jsonPath("$.success", is(false)))
        .andExpect(jsonPath("$.message", is("Unable to update user in Keycloak")));
  }

  @DisplayName("Change Password: Success")
  @Test
  void givenValidPassword_whenChangePassword_thenReturnSuccess() throws Exception {
    // Given
    AuthenticationResponseDTO auth = AuthenticationResponseDTO.builder().accessToken("tempToken").build();
    PasswordDTO passwords = PasswordDTO.builder().currentPassword("@CurrentPass123@").newPassword("NewPassword123@").build();
    given(userManagerService.changePassword(any(PasswordDTO.class), anyString(), anyString()))
        .willReturn(auth);

    // Mock JWT authentication
    JwtAuthenticationToken jwtAuthenticationToken =
        new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
    SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

    // When
    ResultActions response = mockMvc.perform(put("/api/users/change-password")
        .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(passwords)));

    // Then
    response.andExpect(status().isOk()).andExpect(jsonPath("$.success", is(true)))
        .andExpect(jsonPath("$.message", is("User's password updated successfully")));
  }

  @DisplayName("Change Password: Missing Password")
  @Test
  void givenMissingPassword_whenChangePassword_thenReturnBadRequest() throws Exception {
    // Given
    PasswordDTO passwords = PasswordDTO.builder().build();

    // Mock JWT authentication
    JwtAuthenticationToken jwtAuthenticationToken =
        new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_USER")));
    SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

    // When
    ResultActions response = mockMvc.perform(put("/api/users/change-password")
        .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(passwords)));

    // Then
    response.andExpect(status().isBadRequest()).andExpect(jsonPath("$.success", is(false)))
        .andExpect(jsonPath("$.message", is("Validation failed")));
  }

  @DisplayName("Fetch Users: Success")
  @Test
  void givenValidJwt_whenFetchUsers_thenReturnListOfUsers() throws Exception {
    // Given
    given(userManagerService.retrieveUsers(anyString(), anyString())).willReturn(List.of(user));

    // Mock JWT authentication
    JwtAuthenticationToken jwtAuthenticationToken =
        new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
    SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

    // When
    ResultActions response =
        mockMvc.perform(get("/api/users").contentType(MediaType.APPLICATION_JSON));

    // Then
    response.andExpect(status().isOk()).andExpect(jsonPath("$.success", is(true)))
        .andExpect(jsonPath("$.message", is("Users retrieved successfully")))
        .andExpect(jsonPath("$.data[0].email", is("test@test.com")));
  }

  @DisplayName("Fetch User IDs per Pilot: Success")
  @Test
  void givenValidJwt_whenGetUserIdsPerPilot_thenReturnListOfUserIds() throws Exception {
    // Given
    given(userManagerService.retrieveUsersByPilotCode(anyString(), anyString()))
        .willReturn(List.of(user));

    // Mock JWT authentication
    JwtAuthenticationToken jwtAuthenticationToken =
        new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
    SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

    // When
    ResultActions response =
        mockMvc.perform(get("/api/users/ids/pilot/SEW").contentType(MediaType.APPLICATION_JSON));

    // Then
    response.andExpect(status().isOk()).andExpect(jsonPath("$.success", is(true)))
        .andExpect(jsonPath("$.message", is("User IDs for pilot SEW retrieved successfully")))
        .andExpect(jsonPath("$.data[0]", is("12345")));
  }


  @DisplayName("Fetch User by ID: Success")
  @Test
  void givenValidUserId_whenFetchUser_thenReturnUser() throws Exception {
    // Given
    given(userManagerService.retrieveUser(anyString(), anyString())).willReturn(user);

    // Mock JWT authentication
    JwtAuthenticationToken jwtAuthenticationToken =
        new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
    SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

    // When
    ResultActions response = mockMvc.perform(get("/api/users/search").param("userId", "12345"));

    // Then
    response.andExpect(status().isOk()).andExpect(jsonPath("$.success", is(true)))
        .andExpect(jsonPath("$.message", is("User retrieved successfully")))
        .andExpect(jsonPath("$.data.email", is("test@test.com")));
  }

  @DisplayName("Fetch User by ID: Not Found")
  @Test
  void givenInvalidUserId_whenFetchUser_thenReturnNull() throws Exception {
    // Given
    given(userManagerService.retrieveUser(anyString(), anyString())).willReturn(null);

    // Mock JWT authentication
    JwtAuthenticationToken jwtAuthenticationToken =
        new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
    SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

    // When
    ResultActions response =
        mockMvc.perform(get("/api/users/search").param("userId", "invalid-id"));

    // Then
    response.andExpect(status().isOk()) // The API still returns OK but with a null response
        .andExpect(jsonPath("$.success", is(true)))
        .andExpect(jsonPath("$.message", is("User retrieved successfully")))
        .andExpect(jsonPath("$.data").doesNotExist());
  }

  @DisplayName("Fetch User by ID: Internal Server Error")
  @Test
  void givenValidUserId_whenServerErrorOccurs_thenReturnInternalServerError() throws Exception {
    // Given
    given(userManagerService.retrieveUser(anyString(), anyString()))
        .willThrow(new RuntimeException("Server error"));

    // Mock JWT authentication
    JwtAuthenticationToken jwtAuthenticationToken =
        new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
    SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

    // When
    ResultActions response = mockMvc.perform(get("/api/users/search").param("userId", "12345"));

    // Then
    response.andExpect(status().isInternalServerError()).andExpect(jsonPath("$.success", is(false)))
        .andExpect(jsonPath("$.message", is("An unexpected error occurred")));
  }

  @DisplayName("Delete User: Success")
  @Test
  void givenValidJwt_whenDeleteUser_thenReturnSuccess() throws Exception {
    UserDTO existingUser = UserDTO.builder().userId("12345").build();
    // Given
    given(userManagerService.deleteUser(anyString(), anyString())).willReturn(true);
    given(userManagerService.retrieveUser(anyString(), anyString())).willReturn(existingUser);

    // Mock JWT authentication
    JwtAuthenticationToken jwtAuthenticationToken =
        new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
    SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

    // When
    ResultActions response = mockMvc.perform(delete("/api/users/delete").param("userId", "12345"));

    // Then
    response.andExpect(status().isOk()).andExpect(jsonPath("$.success", is(true)))
        .andExpect(jsonPath("$.message", is("User deleted successfully")));
  }

  @DisplayName("Delete User: Failure")
  @Test
  void givenValidJwt_whenDeleteUserFails_thenReturnServerError() throws Exception {
    UserDTO existingUser = UserDTO.builder().userId("12345").build();
    // Given
    given(userManagerService.deleteUser(anyString(), anyString())).willReturn(false);
    given(userManagerService.retrieveUser(anyString(), anyString())).willReturn(existingUser);

    // Mock JWT authentication
    JwtAuthenticationToken jwtAuthenticationToken =
        new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN")));
    SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

    // When
    ResultActions response = mockMvc.perform(delete("/api/users/delete").param("userId", "12345"));

    // Then
    response.andExpect(status().isInternalServerError()).andExpect(jsonPath("$.success", is(false)))
        .andExpect(jsonPath("$.message", is("Unable to delete user from Keycloak")));
  }

  @DisplayName("Forgot Password: Success")
  @Test
  void givenValidEmail_whenForgotPassword_thenReturnSuccess() throws Exception {
    // Given
    String email = "test@test.com";

    // When
    ResultActions response = mockMvc.perform(
        post("/api/users/forgot-password").contentType(MediaType.APPLICATION_JSON).content(email));

    // Then
    response.andExpect(status().isOk()).andExpect(jsonPath("$.success", is(true)))
        .andExpect(jsonPath("$.message", is("Email to reset password sent successfully to user")));
  }

  @DisplayName("Forgot Password: Invalid Email Format")
  @Test
  void givenInvalidEmail_whenForgotPassword_thenReturnBadRequest() throws Exception {
    // Given
    String invalidEmail = "invalid-email";

    // When
    ResultActions response = mockMvc.perform(post("/api/users/forgot-password")
        .contentType(MediaType.APPLICATION_JSON).content(invalidEmail));

    // Then
    response.andExpect(status().isBadRequest()).andExpect(jsonPath("$.success", is(false)))
        .andExpect(jsonPath("$.message", is("Validation failed")));
  }

  @DisplayName("Reset Password: Success")
  @Test
  void givenValidTokenAndPassword_whenResetPassword_thenReturnSuccess() throws Exception {
    // Given
    String token = "userId@resetToken";
    String newPassword = "NewPassword123@";
    given(userManagerService.resetPassword(anyString(), anyString(), anyString())).willReturn(true);

    // When
    ResultActions response = mockMvc.perform(put("/api/users/reset-password").param("token", token)
        .contentType(MediaType.APPLICATION_JSON).content(newPassword));

    // Then
    response.andExpect(status().isOk()).andExpect(jsonPath("$.success", is(true)))
        .andExpect(jsonPath("$.message", is("User's password reset successfully.")));
  }

  @DisplayName("Reset Password: Invalid Token Format")
  @Test
  void givenInvalidToken_whenResetPassword_thenReturnBadRequest() throws Exception {
    // Given
    String invalidToken = "invalid-token";
    String newPassword = "NewPassword123@";

    // When
    ResultActions response = mockMvc.perform(put("/api/users/reset-password")
        .param("token", invalidToken).contentType(MediaType.APPLICATION_JSON).content(newPassword));

    // Then
    response.andExpect(status().isBadRequest()).andExpect(jsonPath("$.success", is(false)))
        .andExpect(jsonPath("$.message", is("Invalid token was given as parameter")));
  }

  @DisplayName("Reset Password: Invalid Password Format")
  @Test
  void givenValidTokenAndInvalidPassword_whenResetPassword_thenReturnBadRequest() throws Exception {
    // Given
    String token = "userId@resetToken";
    String invalidPassword = "weakpass";

    // When
    ResultActions response = mockMvc.perform(put("/api/users/reset-password").param("token", token)
        .contentType(MediaType.APPLICATION_JSON).content(invalidPassword));

    // Then
    response.andExpect(status().isBadRequest()).andExpect(jsonPath("$.success", is(false)))
        .andExpect(jsonPath("$.message", is("Validation failed")));
  }

  @DisplayName("Reset Password: Server Error")
  @Test
  void givenValidTokenAndPassword_whenResetPasswordFails_thenReturnServerError() throws Exception {
    // Given
    String token = "userId@resetToken";
    String newPassword = "NewPassword123@";
    given(userManagerService.resetPassword(anyString(), anyString(), anyString()))
        .willReturn(false);

    // When
    ResultActions response = mockMvc.perform(put("/api/users/reset-password").param("token", token)
        .contentType(MediaType.APPLICATION_JSON).content(newPassword));

    // Then
    response.andExpect(status().isInternalServerError()).andExpect(jsonPath("$.success", is(false)));
  }

  private Jwt createMockJwtToken(String pilotRole, String pilotCode) {
    String tokenValue = "mock.jwt.token";
    Map<String, Object> claims = new HashMap<>();
    claims.put("realm_access", Map.of("roles", List.of("SUPER_ADMIN")));
    claims.put("resource_access", Map.of("modapto", Map.of("roles", List.of("SUPER_ADMIN"))));
    claims.put("sub", "user");
    claims.put("pilot_code", pilotCode);
    claims.put("pilot_role", pilotRole);

    return Jwt.withTokenValue(tokenValue).headers(header -> header.put("alg", "HS256"))
        .claims(claim -> claim.putAll(claims)).build();
  }
}
