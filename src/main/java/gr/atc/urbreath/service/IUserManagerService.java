package gr.atc.urbreath.service;

import java.util.List;

import gr.atc.urbreath.dto.AuthenticationResponseDTO;
import gr.atc.urbreath.dto.CredentialsDTO;
import gr.atc.urbreath.dto.PasswordDTO;
import gr.atc.urbreath.dto.UserDTO;
import gr.atc.urbreath.dto.keycloak.UserRepresentationDTO;

public interface IUserManagerService {

  AuthenticationResponseDTO authenticate(CredentialsDTO credentials);

  AuthenticationResponseDTO refreshToken(String refreshToken);

  String createUser(UserDTO userDTO, String token);

  boolean updateUser(UserDTO userDTO, String userId, String token);

  List<UserDTO> retrieveUsers(String token, String pilot);

  UserDTO retrieveUser(String userId, String token);

  boolean deleteUser(String userId, String token);

  AuthenticationResponseDTO changePassword(PasswordDTO passwords, String userId, String token);

  UserRepresentationDTO retrieveUserByEmail(String email, String token);

  UserRepresentationDTO retrieveUserById(String userId, String token);

  void assignRolesToUser(UserDTO newUserDetails, UserDTO existingUserDetails, String userId, String token);

  boolean assignRealmRoles(String pilotRole, String userId, String token);

  void assignRealmManagementRoles(String pilotRole, String userId, String token);

  void logoutUser(String userId, String token);

  List<UserDTO> retrieveUsersByPilotCode(String pilotCode, String token);

  boolean activateUser(String userId, String activationToken, String password);

  void forgotPassword(String email);

  boolean resetPassword(String userId, String resetToken, String password);
}
