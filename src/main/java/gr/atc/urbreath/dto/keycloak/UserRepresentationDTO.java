package gr.atc.urbreath.dto.keycloak;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;

import gr.atc.urbreath.dto.UserDTO;
import gr.atc.urbreath.enums.PilotRole;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserRepresentationDTO {

  private static final String PILOT_CODE = "pilot_code";
  private static final String PILOT_ROLE = "pilot_role";;
  private static final String ACTIVATION_TOKEN = "activation_token";
  private static final String RESET_TOKEN = "reset_token";
  private static final String ACTIVATION_EXPIRY = "activation_expiry";
  private static final String SUPER_ADMIN_PILOT = "ALL";


  @JsonProperty
  private String id;
  
  @JsonProperty("email")
  private String email;

  @JsonProperty("emailVerified")
  private boolean emailVerified;

  @JsonProperty("enabled")
  private boolean enabled;

  @JsonProperty("firstName")
  private String firstName;

  @JsonProperty("lastName")
  private String lastName;

  @JsonProperty("username")
  private String username;

  @JsonProperty("credentials")
  private List<CredentialRepresentationDTO> credentials;

  @JsonProperty("attributes")
  private Map<String, List<String>> attributes;

  @JsonProperty("groups")
  private List<String> groups;

  /**
   * Transform a UserDTO to User Representation
   * 
   * @param user : UserDTO with the updates
   * @param existingUser : Existing User Representation if provided
   * @return UserRepresentationDTO
   */
  public static UserRepresentationDTO toUserRepresentationDTO(UserDTO user,
      UserRepresentationDTO existingUser) {
    if (user == null)
      return existingUser;

    UserRepresentationDTO keycloakUser;
    // User will be by default disabled until he activates its account and create a new password
    if (existingUser == null) {
      keycloakUser = new UserRepresentationDTO();
      keycloakUser.setEnabled(false);
    } else {
      keycloakUser = existingUser;
    }

    updateUserDetails(user, keycloakUser, existingUser);
    updateUserAttributes(user, keycloakUser);
    updateUserTokenAttributes(user, keycloakUser, existingUser);

    return keycloakUser;
  }

  /**
   * Transform a UserRepresentation of Keycloak into UserDTO in User Manager
   * 
   * @param keycloakUser : UserRepresentationDTO
   * @return UserDTO
   */
  public static UserDTO toUserDTO(UserRepresentationDTO keycloakUser) {
    if (keycloakUser == null)
      return null;

    return UserDTO.builder().userId(keycloakUser.getId())
        .email(keycloakUser.getEmail())
        .firstName(keycloakUser.getFirstName())
        .lastName(keycloakUser.getLastName())
        .username(keycloakUser.getUsername())
        .pilotCode(getPilotCodeAttribute(keycloakUser))
        .pilotRole(getPilotRoleAttribute(keycloakUser))
        .activationToken(getAttributeValue(keycloakUser, ACTIVATION_TOKEN))
        .activationExpiry(getAttributeValue(keycloakUser, ACTIVATION_EXPIRY))
        .resetToken(getAttributeValue(keycloakUser, RESET_TOKEN))
        .tokenFlagRaised(false)
        .build();
  }

  private static String getAttributeValue(UserRepresentationDTO user, String key) {
    if (user.getAttributes() == null || !user.getAttributes().containsKey(key)
        || user.getAttributes().get(key).isEmpty()) {
      return null;
    }
    return user.getAttributes().get(key).getFirst();
  }

  private static String getPilotCodeAttribute(UserRepresentationDTO user) {
    return getAttributeValue(user, PILOT_CODE);
  }

  private static PilotRole getPilotRoleAttribute(UserRepresentationDTO user) {
    String pilotRole =  getAttributeValue(user, PILOT_ROLE);
    return pilotRole != null ? PilotRole.valueOf(pilotRole) : null;
  }

  /**
   * Update User Details and Credentials
   *
   * @param user : User input data
   * @param keycloakUser : Updated version of Keycloak user
   * @param existingUser : Existing user in Keycloak
   */
  private static void updateUserDetails(UserDTO user, UserRepresentationDTO keycloakUser,
      UserRepresentationDTO existingUser) {
    if (user.getFirstName() != null) {
      keycloakUser.setFirstName(user.getFirstName());
    }

    if (user.getLastName() != null) {
      keycloakUser.setLastName(user.getLastName());
    }

    if (user.getEmail() != null) {
      keycloakUser.setEmail(user.getEmail());
      keycloakUser.setEmailVerified(true);
    }

    if (user.getUsername() != null && existingUser == null) {
      keycloakUser.setUsername(user.getUsername());
    }

    if (user.getPassword() != null && existingUser != null) {
      keycloakUser.setCredentials(List.of(CredentialRepresentationDTO.builder().temporary(false)
          .type("password").value(user.getPassword()).build()));
    }
  }

  /**
   * Update User and Pilot Roles and Groups of User
   *
   * @param user : User input data
   * @param keycloakUser : Updated version of Keycloak user
   */
  private static void updateUserAttributes(UserDTO user, UserRepresentationDTO keycloakUser) {
    // Attributes Field
    if (keycloakUser.getAttributes() == null) {
      keycloakUser.setAttributes(new HashMap<>());
    }

    if (user.getPilotRole() != null) {
      keycloakUser.getAttributes().put(PILOT_ROLE, List.of(user.getPilotRole().toString()));
    }

    if (user.getPilotCode() != null) {
      if (!user.getPilotCode().equalsIgnoreCase(SUPER_ADMIN_PILOT)) {
        String pilotType = "/" + user.getPilotCode();
        keycloakUser.setGroups(List.of(pilotType));
      }
      keycloakUser.getAttributes().put(PILOT_CODE, List.of(user.getPilotCode()));
    }
  }

  /**
   * Update user token attributes
   *
   * @param user : User input data
   * @param keycloakUser : Updated version of Keycloak user
   * @param existingUser : Existing user in Keycloak
   */
  private static void updateUserTokenAttributes(UserDTO user, UserRepresentationDTO keycloakUser,
      UserRepresentationDTO existingUser) {
    // Set activation token and expiration time as attributes - Two cases can be observed: 1) Create
    // a new user 2) Activate user
    if (existingUser == null && user.getActivationExpiry() != null
        && user.getActivationToken() != null && !user.isTokenFlagRaised()) { // Creation of a new
                                                                             // user
      keycloakUser.getAttributes().put(ACTIVATION_TOKEN, List.of(user.getActivationToken()));
      keycloakUser.getAttributes().put(ACTIVATION_EXPIRY, List.of(user.getActivationExpiry()));
    } else if (user.isTokenFlagRaised() && user.getActivationToken() != null
        && keycloakUser.getAttributes() != null) { // This will apply only after the user has been
                                                   // activated
      keycloakUser.getAttributes().remove(ACTIVATION_TOKEN);
      keycloakUser.getAttributes().remove(ACTIVATION_EXPIRY);
      keycloakUser.setEnabled(true); // Enable user
    }

    // Set Reset Token if exists (Case of forgot password) or Remove it in case of Reset Password
    if (user.getResetToken() != null && keycloakUser.getAttributes() != null) {
      if (!user.isTokenFlagRaised()) {
        keycloakUser.getAttributes().put(RESET_TOKEN, List.of(user.getResetToken()));
      } else {
        keycloakUser.getAttributes().remove(RESET_TOKEN);
      }
    }
  }
}
