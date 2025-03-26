package gr.atc.urbreath.controller;

import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import gr.atc.urbreath.dto.AuthenticationResponseDTO;
import gr.atc.urbreath.dto.CredentialsDTO;
import gr.atc.urbreath.dto.PasswordDTO;
import gr.atc.urbreath.dto.UserDTO;
import gr.atc.urbreath.dto.keycloak.UserRepresentationDTO;
import gr.atc.urbreath.enums.PilotRole;
import gr.atc.urbreath.service.IEmailService;
import gr.atc.urbreath.service.IUserManagerService;
import gr.atc.urbreath.util.JwtUtils;
import gr.atc.urbreath.validation.ValidPassword;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@AllArgsConstructor
@RequestMapping("/api/users")
@Slf4j
public class UserManagerController {

  private final IUserManagerService userManagerService;

  private final IEmailService emailService;

  /**
   * POST user credentials to generate a token from Keycloak
   *
   * @param credentials : Email and password of user
   * @return AuthenticationResponse
   */
  @Operation(summary = "Authenticate user given credentials", security = @SecurityRequirement(name = ""))
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "Authentication token generated successfully", content = {@Content(mediaType = "application/json", schema = @Schema(implementation = AuthenticationResponseDTO.class))}),
      @ApiResponse(responseCode = "400", description = "Validation failed")})
  @PostMapping(value = "/authenticate")
  public ResponseEntity<BaseResponse<AuthenticationResponseDTO>> authenticateUser(
      @Valid @RequestBody CredentialsDTO credentials) {

    AuthenticationResponseDTO response = userManagerService.authenticate(credentials);

    return new ResponseEntity<>(
          BaseResponse.success(response, "Authentication token generated successfully"),
          HttpStatus.OK);
  }

  /**
   * POST refresh token to refresh user's token before expiration
   *
   * @param refreshToken : Refresh Token
   * @return AuthenticationResponse
   */
  @Operation(summary = "Refresh user Token", security = @SecurityRequirement(name = ""))
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "Authentication token generated successfully", content = {@Content(mediaType = "application/json", schema = @Schema(implementation = AuthenticationResponseDTO.class))}),
      @ApiResponse(responseCode = "400",
          description = "Invalid / No input was given for requested resource")})
  @PostMapping(value = "/refresh-token")
  public ResponseEntity<BaseResponse<AuthenticationResponseDTO>> refreshToken(
      @RequestParam(name = "token") String refreshToken) {

    AuthenticationResponseDTO response = userManagerService.refreshToken(refreshToken);

    return new ResponseEntity<>(
          BaseResponse.success(response, "Authentication token generated successfully"),
          HttpStatus.OK);
  }

  /**
   * Activate User and update his/her password
   *
   * @param token : Activation token with userId information and activation token stored in Keycloak
   * @param password : User's new password
   * @return message of success or failure
   */
  @Operation(summary = "Activate user", security = @SecurityRequirement(name = ""))
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200",
          description = "User activated and password updated successfully."),
      @ApiResponse(responseCode = "400", description = "Invalid token was given as parameter"),
      @ApiResponse(responseCode = "409", description = "User is already activated"),
      @ApiResponse(responseCode = "500",
          description = "Due to an internal error, user has not been activated!"),})
  @PostMapping(value = "/activate")
  public ResponseEntity<BaseResponse<String>> activateUser(@RequestParam String token,
      @ValidPassword @RequestBody String password) {

    // Split the User ID and the Keycloak Activation Token
    List<String> tokenData = List.of(token.split("@"));

    // Ensure token inserted is valid - UserID # Activation Token
    if (tokenData.size() != 2)
      return new ResponseEntity<>(BaseResponse.error("Invalid token was given as parameter"),
          HttpStatus.BAD_REQUEST);

    String userId = tokenData.getFirst();
    String activationToken = tokenData.getLast();

    if (userManagerService.activateUser(userId, activationToken, password))
      return new ResponseEntity<>(
          BaseResponse.success(null, "User activated and password updated successfully."),
          HttpStatus.OK);
    else
      return new ResponseEntity<>(
          BaseResponse.error(null, "Due to an internal error, user has not been activated!"),
          HttpStatus.INTERNAL_SERVER_ERROR);
  }

  /**
   * Logout user
   *
   * @param jwt : JWT Token
   * @return message of success or failure
   */
  @Operation(summary = "Logout user", security = @SecurityRequirement(name = "bearerToken"))
  @ApiResponses(
      value = {@ApiResponse(responseCode = "200", description = "User logged out successfully"),
          @ApiResponse(responseCode = "400",
              description = "Invalid request: Either credentials or token must be provided!"),
          @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
          @ApiResponse(responseCode = "403",
              description = "Invalid authorization parameters. Check JWT or CSRF Token"),})
  @PostMapping(value = "/logout")
  public ResponseEntity<BaseResponse<String>> logoutUser(@AuthenticationPrincipal Jwt jwt) {

    String token = jwt.getTokenValue();
    String userId = JwtUtils.extractUserId(jwt);
    userManagerService.logoutUser(userId, token);
    return new ResponseEntity<>(BaseResponse.success(null, "User logged out successfully"),
        HttpStatus.OK);
  }

  /**
   * Creation of a new User by Super-Admin or Admin Depending on the type of User uses will be able
   * to create new users - Admins can only create personnel inside their organization - Super Admins
   * can create personnel for all pilots and create new Super Admins also
   *
   * @param user : User information
   * @param jwt : JWT Token
   * @return message of success or failure
   */
  @Operation(summary = "Create a new user in Keycloak",
      security = @SecurityRequirement(name = "bearerToken"))
  @ApiResponses(value = {
      @ApiResponse(responseCode = "201", description = "User created successfully",
          content = {@Content(mediaType = "application/json",
              schema = @Schema(implementation = AuthenticationResponseDTO.class))}),
      @ApiResponse(responseCode = "400", description = "Invalid request: Either credentials or token must be provided!"),
      @ApiResponse(responseCode = "400", description = "Validation failed"),
      @ApiResponse(responseCode = "401", description = "Authentication process failed!"),
      @ApiResponse(responseCode = "403", description = "Invalid authorization parameters. Check JWT or CSRF Token"),
      @ApiResponse(responseCode = "403", description = "Only Super Admins can create other Super Admin users."),
      @ApiResponse(responseCode = "403", description = "Admins can only create personnel inside their organization"),
      @ApiResponse(responseCode = "409", description = "User already exists in Keycloak"),
      @ApiResponse(responseCode = "409", description = "User with the given email already exists in Keycloak"),
      @ApiResponse(responseCode = "500", description = "Unable to create user in Keycloak")})
  @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN')")
  @PostMapping(value = "/create")
  public ResponseEntity<BaseResponse<String>> createUser(@RequestBody UserDTO user,
      @AuthenticationPrincipal Jwt jwt) {

    // Ensure that all required fields are given and are valid to create a new user
    if (!isValidUserData(user))
      return new ResponseEntity<>(
          BaseResponse.error("Validation failed", "Input data are missing or are empty"),
          HttpStatus.BAD_REQUEST);

    // Ensure that if only Super Admins can create new Super Admins
    if (user.getPilotRole().equals(PilotRole.SUPER_ADMIN)
        && !JwtUtils.extractPilotRole(jwt).equalsIgnoreCase(PilotRole.SUPER_ADMIN.toString()))
      return new ResponseEntity<>(BaseResponse.error("Unauthorized action",
          "Only Super Admins can create other Super Admin users."), HttpStatus.FORBIDDEN);

    // Ensure that Admins can create personnel only inside their organization
    if (JwtUtils.extractPilotRole(jwt).equals(PilotRole.ADMIN.toString())
        && !JwtUtils.extractPilotCode(jwt).equalsIgnoreCase(user.getPilotCode()))
      return new ResponseEntity<>(BaseResponse.error("Unauthorized action",
          "Admins can only create personnel inside their organization"), HttpStatus.FORBIDDEN);

    // Ensure that user doesn't exist in Auth Server
    UserRepresentationDTO keycloakUser =
        userManagerService.retrieveUserByEmail(user.getEmail(), jwt.getTokenValue());
    if (keycloakUser != null)
      return new ResponseEntity<>(
          BaseResponse.error("User with the given email already exists in Keycloak"),
          HttpStatus.CONFLICT);

    // Create activation token
    user.setActivationToken(UUID.randomUUID().toString());
    user.setTokenFlagRaised(false);
    user.setActivationExpiry(String.valueOf(System.currentTimeMillis() + 86400000)); // 24 Hours expiration time

    String token = jwt.getTokenValue();
    String userId = userManagerService.createUser(user, token);

    // Assign the essential roles to the User Asynchronously
    userManagerService.assignRolesToUser(user, null, userId, token);

    // Send activation link async
    String activationToken = userId.concat("@").concat(user.getActivationToken()); // Token in activation Link will be: User ID + @ + Activation Token
    emailService.sendActivationLink(user.getUsername(), user.getEmail(), activationToken);

    return new ResponseEntity<>(
          BaseResponse.success(userId, "User created successfully"),
          HttpStatus.CREATED);
  }

  /**
   * Validate that all fields are inserted and are valid in order to create a new User
   *
   * @param user : User information
   * @return True on success, False on error
   */
  private boolean isValidUserData(UserDTO user) {
    if (user == null) {
      return false;
    }

    // Ensure all required fields are non-null
    if (user.getUsername() == null || user.getEmail() == null || user.getFirstName() == null
            || user.getLastName() == null ||  user.getPilotRole() == null
            || user.getPilotCode() == null) {
      return false;
    }

    // Ensure no spaces in specific fields
    return !user.getUsername().contains(" ")
              && !user.getEmail().contains(" ")
              && !user.getFirstName().contains(" ")
              && !user.getLastName().contains(" ");
  }

  /**
   * Update user's information in Keycloak
   *
   * @param user: UserDTO information
   * @param jwt: JWT Token
   * @return Message of success or failure
   */
  @Operation(summary = "Update user's information in Keycloak",
      security = @SecurityRequirement(name = "bearerToken"))
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "User updated successfully"),
      @ApiResponse(responseCode = "400",
          description = "Invalid request: Either credentials or token must be provided!"),
      @ApiResponse(responseCode = "400", description = "Validation failed"),
      @ApiResponse(responseCode = "400", description = "An unexpected error occured"),
      @ApiResponse(responseCode = "403",
          description = "Invalid JWT Token Attributes"),
      @ApiResponse(responseCode = "403",
          description = "Invalid authorization parameters. Check JWT or CSRF Token"),
      @ApiResponse(responseCode = "403",
          description = "User of type 'ADMIN' can only update user's inside their organization"),
      @ApiResponse(responseCode = "500", description = "Unable to update user in Keycloak")})
  @PutMapping(value = "/update")
  public ResponseEntity<BaseResponse<String>> updateUser(@RequestBody UserDTO user,
      @AuthenticationPrincipal Jwt jwt, @RequestParam String userId) {

    String jwtRole = JwtUtils.extractPilotRole(jwt);
    String jwtPilot = JwtUtils.extractPilotCode(jwt);

    UserRepresentationDTO existingUser =
        userManagerService.retrieveUserById(userId, jwt.getTokenValue());
    if (existingUser == null)
      return new ResponseEntity<>(BaseResponse.error("User not found in Keycloak"),
          HttpStatus.EXPECTATION_FAILED);

    UserDTO existingUserDTO = UserRepresentationDTO.toUserDTO(existingUser);

    if (jwtRole.equals(PilotRole.ADMIN.toString())
        && !jwtPilot.equalsIgnoreCase(existingUserDTO.getPilotCode()))
      return new ResponseEntity<>(
          BaseResponse
              .error("User of type 'ADMIN' can only update user's inside their organization"),
          HttpStatus.FORBIDDEN);
    
    String token = jwt.getTokenValue();
    // Update users
    if (userManagerService.updateUser(user, userId, token)){
      // Assign the essential roles to the User Asynchronously after the Update
      userManagerService.assignRolesToUser(user, existingUserDTO, userId, token);
      return new ResponseEntity<>(BaseResponse.success(null, "User updated successfully"),
          HttpStatus.OK);
    } else
      return new ResponseEntity<>(BaseResponse.error("Unable to update user in Keycloak"),
          HttpStatus.INTERNAL_SERVER_ERROR);
  }

  /**
   * Change user's password in Keycloak
   *
   * @param passwords: Current and New passwords
   * @param jwt: JWT Token
   * @return Message of success or failure
   */
  @Operation(summary = "Change user's password in Keycloak",
      security = @SecurityRequirement(name = "bearerToken"))
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "User's password updated successfully"),
      @ApiResponse(responseCode = "400",
          description = "Invalid request: Either credentials or token must be provided!"),
      @ApiResponse(responseCode = "400", description = "Validation failed"),
      @ApiResponse(responseCode = "401", description = "Invalid authorization credentials provided."),
      @ApiResponse(responseCode = "403",
          description = "Invalid authorization parameters. Check JWT or CSRF Token"),
      @ApiResponse(responseCode = "404", description = "User with this ID not found in Keycloak"),
      @ApiResponse(responseCode = "500",
          description = "Unable to update user's password in Keycloak")})
  @PutMapping(value = "/change-password")
  public ResponseEntity<BaseResponse<AuthenticationResponseDTO>> changePassword(@Valid @RequestBody PasswordDTO passwords,
      @AuthenticationPrincipal Jwt jwt) {
  
    String userId = JwtUtils.extractUserId(jwt);
    AuthenticationResponseDTO newAuthentication = userManagerService.changePassword(passwords, userId, jwt.getTokenValue());
    if (newAuthentication != null)
      return new ResponseEntity<>(
          BaseResponse.success(newAuthentication, "User's password updated successfully"), HttpStatus.OK);
    else
      return new ResponseEntity<>(
          BaseResponse.error("Unable to update user's password in Keycloak"),
          HttpStatus.INTERNAL_SERVER_ERROR);
  }

   /**
   * Forget user's password functionality
   *
   * @param email: Email
   * @return Message of success or failure
   */
  @Operation(summary = "Forgot password functionality that send email to user to reset it", security = @SecurityRequirement(name = ""))
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "Email to reset password sent successfully to user"),
      @ApiResponse(responseCode = "400", description = "Validation Error"),
      @ApiResponse(responseCode = "404", description = "User with this email does not exist in Keycloak"),
      @ApiResponse(responseCode = "409", description = "User is not activated. Password can not be reset")
  })
  @PostMapping(value = "/forgot-password")
  public ResponseEntity<BaseResponse<String>> forgotPassword(@RequestBody @Email String email) {
    userManagerService.forgotPassword(email);
    return new ResponseEntity<>(BaseResponse.success(null, "Email to reset password sent successfully to user"), HttpStatus.OK);
  }

  /**
   * Reset user password given a token
   *
   * @param token : Reset Token
   * @param password : New Password
   * @return Message of success or failure
   */
  @Operation(summary = "Reset user's password functionality given a reset token", security = @SecurityRequirement(name = ""))
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "Email sent successfully to user"),
      @ApiResponse(responseCode = "400", description = "Invalid token was given as parameter"),
      @ApiResponse(responseCode = "400", description = "Validation Error"),
          @ApiResponse(responseCode = "403", description = "Reset token is wrong or there is no reset token for specific user. Please contact the admin of your organization"),
          @ApiResponse(responseCode = "404", description = "User with this ID not found in Keycloak"),
      @ApiResponse(responseCode = "500",description = "Unable to reset user's password in Keycloak")})
  @PutMapping(value = "/reset-password")
  public ResponseEntity<BaseResponse<String>> resetPassword(@RequestParam String token, @ValidPassword @RequestBody String password) {
    // Split the User ID and the Keycloak Activation Token
    List<String> tokenData = List.of(token.split("@"));

    // Ensure token inserted is valid - UserID # Activation Token
    if (tokenData.size() != 2)
      return new ResponseEntity<>(BaseResponse.error("Invalid token was given as parameter"),
          HttpStatus.BAD_REQUEST);

    String userId = tokenData.getFirst();
    String resetToken = tokenData.getLast();

    // Reset password functionality
    if (userManagerService.resetPassword(userId, resetToken, password))
      return new ResponseEntity<>(
          BaseResponse.success(null, "User's password reset successfully."), HttpStatus.OK);
    else
      return new ResponseEntity<>(BaseResponse.error(null, "Unable to reset user's password in Keycloak"), HttpStatus.INTERNAL_SERVER_ERROR);
  }

  /**
   * Retrieve all users from Keycloak - Only for Super Admins / Pilot Admins
   *
   * @param jwt: JWT Token
   * @return List<UserDTO>
   */
  @Operation(summary = "Retrieve all users from Keycloak",
      security = @SecurityRequirement(name = "bearerToken"))
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "Users retrieved successfully",
          content = {@Content(mediaType = "application/json",
              schema = @Schema(implementation = UserDTO.class))}),
      @ApiResponse(responseCode = "400",
          description = "Invalid request: Either credentials or token must be provided!"),
      @ApiResponse(responseCode = "400", description = "An unexpected error occured"),
      @ApiResponse(responseCode = "403",
          description = "Invalid authorization parameters. Check JWT or CSRF Token"),
      @ApiResponse(responseCode = "403",
          description = "Token inserted is invalid. It does not contain any information about the pilot")})
  @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN')")
  @GetMapping
  public ResponseEntity<BaseResponse<List<UserDTO>>> retrieveUsers(@AuthenticationPrincipal Jwt jwt) {
    String pilot = JwtUtils.extractPilotCode(jwt);
    if (pilot == null)
      return new ResponseEntity<>(
          BaseResponse.error(
              "Token inserted is invalid. It does not contain any information about the pilot"),
          HttpStatus.FORBIDDEN);
    return new ResponseEntity<>(
        BaseResponse.success(userManagerService.retrieveUsers(jwt.getTokenValue(), pilot),
            "Users retrieved successfully"),
        HttpStatus.OK);
  }

  /**
   * Search user by ID from Keycloak - Only for Super Admins / Pilot Admins
   *
   * @param userId: ID of the user
   * @param jwt: JWT Token
   * @return UserDTO
   */
  @Operation(summary = "Search user by ID from Keycloak",
      security = @SecurityRequirement(name = "bearerToken"))
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "User retrieved successfully",
          content = {@Content(mediaType = "application/json",
              schema = @Schema(implementation = UserDTO.class))}),
      @ApiResponse(responseCode = "400",
          description = "Invalid request: Either credentials or token must be provided!"),
      @ApiResponse(responseCode = "400", description = "An unexpected error occured"),
      @ApiResponse(responseCode = "403",
          description = "Invalid authorization parameters. Check JWT or CSRF Token"),})
  @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN')")
  @GetMapping("/search")
  public ResponseEntity<BaseResponse<UserDTO>> retrieveUser(@RequestParam String userId,
      @AuthenticationPrincipal Jwt jwt) {
    return new ResponseEntity<>(
        BaseResponse.success(userManagerService.retrieveUser(userId, jwt.getTokenValue()),
            "User retrieved successfully"),
        HttpStatus.OK);
  }

  /**
   * Delete user from Keycloak - Only for Super Admins
   *
   * @param userId: ID of the user
   * @param jwt: JWT Token
   * @return Message of success or failure
   */
  @Operation(summary = "Delete a user by ID from Keycloak",
      security = @SecurityRequirement(name = "bearerToken"))
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200", description = "User deleted successfully",
          content = {@Content(mediaType = "application/json",
              schema = @Schema(implementation = UserDTO.class))}),
      @ApiResponse(responseCode = "400",
          description = "Invalid request: Either credentials or token must be provided!"),
      @ApiResponse(responseCode = "400", description = "An unexpected error occured"),
      @ApiResponse(responseCode = "403",
          description = "Invalid authorization parameters. Check JWT or CSRF Token"),
      @ApiResponse(responseCode = "403", description = "Unauthorized action. Admin users can only delete people inside their organization"),
      @ApiResponse(responseCode = "409", description = "User not found in Keycloak"),
      @ApiResponse(responseCode = "500", description = "Unable to delete user from Keycloak")})
  @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN')")
  @DeleteMapping("/delete")
  public ResponseEntity<BaseResponse<String>> deleteUser(@RequestParam String userId,
      @AuthenticationPrincipal Jwt jwt) {
    String pilot = JwtUtils.extractPilotCode(jwt);
    String pilotRole = JwtUtils.extractPilotRole(jwt);

    // Try locate user
    UserDTO existingUser = userManagerService.retrieveUser(userId,jwt.getTokenValue());
    if (existingUser == null)
      return new ResponseEntity<>(BaseResponse.error("User not found in Keycloak"),
          HttpStatus.CONFLICT);

    // Validate that ADMIN users can only delete Users inside their plant
    if (pilotRole.equalsIgnoreCase(PilotRole.ADMIN.toString()) && !pilot.equalsIgnoreCase(existingUser.getPilotCode()))
      return new ResponseEntity<>(BaseResponse.error("Unauthorized action. Admin users can only delete people inside their organization"),
          HttpStatus.FORBIDDEN);

    // Delete the User
    if (userManagerService.deleteUser(userId, jwt.getTokenValue()))
      return new ResponseEntity<>(BaseResponse.success(null, "User deleted successfully"),
          HttpStatus.OK);
    else
      return new ResponseEntity<>(BaseResponse.error("Unable to delete user from Keycloak"),
          HttpStatus.INTERNAL_SERVER_ERROR);
  }

  /**
   * Retrieve all user IDs from Keycloak
   *
   * @param jwt: JWT Token
   * @return List<UserDTO>
   */
  @Operation(summary = "Retrieve all user IDs for a specific pilot from Keycloak",
      security = @SecurityRequirement(name = "bearerToken"))
  @ApiResponses(
      value = {@ApiResponse(responseCode = "200", description = "User IDs retrieved successfully"),
          @ApiResponse(responseCode = "400",
              description = "Invalid request: Either credentials or token must be provided!"),
          @ApiResponse(responseCode = "400", description = "An unexpected error occured"),
          @ApiResponse(responseCode = "403",
              description = "Invalid authorization parameters. Check JWT or CSRF Token"),
          @ApiResponse(responseCode = "500",
              description = "Unable to locate requested group ID in Keycloak")})
  @GetMapping("/ids/pilot/{pilotCode}")
  public ResponseEntity<BaseResponse<List<String>>> getAllUserIdsByPilotCode(
      @AuthenticationPrincipal Jwt jwt, @PathVariable String pilotCode) {
    List<UserDTO> users =
        userManagerService.retrieveUsersByPilotCode(pilotCode.toUpperCase(), jwt.getTokenValue());
    return new ResponseEntity<>(
        BaseResponse.success(users.stream().map(UserDTO::getUserId).toList(),
            "User IDs for pilot " + pilotCode + " retrieved successfully"),
        HttpStatus.OK);
  }

  /**
   * Return the authentication information based on the inserted token
   *
   * @param authentication : JWT token
   * @return authentication information
   */
  @Operation(summary = "Retrieve Authentication Information based on the JWT token",
      security = @SecurityRequirement(name = "bearerToken"))
  @ApiResponses(value = {
      @ApiResponse(responseCode = "200",
          description = "Information about Authentication Information based on the JWT token",
          content = {@Content(mediaType = "application/json",
              schema = @Schema(implementation = Authentication.class))}),
      @ApiResponse(responseCode = "403",
          description = "Invalid authorization parameters. Check JWT or CSRF Token")})
  @GetMapping(value = "/auth-info")
  public ResponseEntity<Authentication> getAuthInfo(Authentication authentication) {
    return new ResponseEntity<>(authentication, HttpStatus.OK);
  }
}
