package gr.atc.urbreath.controller;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import gr.atc.urbreath.dto.PilotDTO;
import gr.atc.urbreath.enums.PilotRole;
import gr.atc.urbreath.service.IAdminService;
import gr.atc.urbreath.util.JwtUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;

@RequestMapping("api/admin")
@RestController
@AllArgsConstructor
public class AdminController {
    /**
     * System Roles: Roles that are assigned to a User when he signs-up and define their priveleges
     * Pilots: Use case cities
     */
    private final IAdminService adminService;

    /**
     * GET all system Roles or filter by Pilot
     *
     * @param jwt : JWT Token
     * @return List<String> : List of Pilot Roles
     */
    @Operation(summary = "Retrieve all system roles", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "System roles retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Invalid or missing Token"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters"),
    })
    @PreAuthorize("hasAnyAuthority('ROLE_SUPER_ADMIN', 'ROLE_ADMIN')")
    @GetMapping("/roles")
    public ResponseEntity<BaseResponse<List<String>>> getAllSystemRoles(@AuthenticationPrincipal Jwt jwt) {
      // Validate token proper format
      String role = JwtUtils.extractPilotRole(jwt);

      // Set the flag to true or false according to the Role of User
      boolean isSuperAdmin = !role.equalsIgnoreCase(PilotRole.ADMIN.toString());

      return new ResponseEntity<>(BaseResponse.success(adminService.retrieveAllSystemRoles(jwt.getTokenValue(), isSuperAdmin), "System roles retrieved successfully"), HttpStatus.OK);
    }


    /**
     * GET all Pilots
     *
     * @param jwt : JWT Token
     * @return List<String> : List of Pilots
     */
    @Operation(summary = "Retrieve all pilots from Keycloak", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Pilot codes retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Invalid or missing Token"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters"),
    })
    @PreAuthorize("hasAuthority('ROLE_SUPER_ADMIN')")
    @GetMapping("/pilots")
    public ResponseEntity<BaseResponse<List<String>>> getAllPilots(@AuthenticationPrincipal Jwt jwt) {
        return new ResponseEntity<>(BaseResponse.success(adminService.retrieveAllPilots(jwt.getTokenValue()), "Pilot codes retrieved successfully"), HttpStatus.OK);
    }


    /**
     * Create a new Pilot in Keycloak
     *
     * @param jwt : JWT Token
     * @return Success message or Failure Message
     */
    @Operation(summary = "Create a new Pilot / Organization", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Pilot created successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid input data"),
            @ApiResponse(responseCode = "401", description = "Invalid or missing Token"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters"),
            @ApiResponse(responseCode = "409", description = "Pilot already exists in Keycloak"),
            @ApiResponse(responseCode = "500", description = "Unable to create and store the new piloit")
    })
    @PreAuthorize("hasAuthority('ROLE_SUPER_ADMIN')")
    @PostMapping("/pilot")
    public ResponseEntity<BaseResponse<Void>> createPilot(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody PilotDTO pilotData) {
        // Create Pilot in Keycloak
        if (adminService.createPilot(jwt.getTokenValue(), pilotData))
            return new ResponseEntity<>(BaseResponse.success(null,"Pilot created successfully"), HttpStatus.CREATED);
        else
            return new ResponseEntity<>(BaseResponse.error("Unable to create and store the new pilot"), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * Delete a Pilot in Keycloak
     *
     * @param jwt : JWT Token
     * @return Success message or Failure Message
     */
    @Operation(summary = "Delete an existing Pilot / Organization", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Pilot deleted successfully"),
            @ApiResponse(responseCode = "401", description = "Invalid or missing Token"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters"),
            @ApiResponse(responseCode = "409", description = "No information found for the designated Pilot"),
            @ApiResponse(responseCode = "500", description = "Unable to delete the specified pilot")
    })
    @PreAuthorize("hasAuthority('ROLE_SUPER_ADMIN')")
    @DeleteMapping("/pilot/{pilotName}")
    public ResponseEntity<BaseResponse<Void>> deletePilot(@AuthenticationPrincipal Jwt jwt, @PathVariable String pilotName) {
        // Delete Pilot in Keycloak
        if (adminService.deletePilot(jwt.getTokenValue(), pilotName.trim().toUpperCase()))
            return new ResponseEntity<>(BaseResponse.success(null,"Pilot deleted successfully"), HttpStatus.OK);
        else
            return new ResponseEntity<>(BaseResponse.error("Unable to delete the specified pilot"), HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * Update a Pilot / Organization in Keycloak
     *
     * @param pilotName : Pilot name
     * @param pilotData : Pilot new Data
     * @param jwt   : JWT Token
     * @return Success message or Failure Message
     */
    @Operation(summary = "Update an existing Pilot / Organization", security = @SecurityRequirement(name = "bearerToken"))
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Pilot updated successfully"),
            @ApiResponse(responseCode = "401", description = "Invalid or missing Token"),
            @ApiResponse(responseCode = "403", description = "Invalid authorization parameters"),
            @ApiResponse(responseCode = "409", description = "No information found for the designated Pilot"),
            @ApiResponse(responseCode = "500", description = "Unable to update the specified pilot")
    })
    @PreAuthorize("hasAuthority('ROLE_SUPER_ADMIN')")
    @PutMapping("/pilot/{pilotName}")
    public ResponseEntity<BaseResponse<Void>> updatePilot(@AuthenticationPrincipal Jwt jwt, @PathVariable String pilotName, @RequestBody PilotDTO pilotData) {
        // Update Pilot in Keycloak
        if (adminService.updatePilot(jwt.getTokenValue(), pilotName.trim().toUpperCase(), pilotData))
            return new ResponseEntity<>(BaseResponse.success(null,"Pilot updated successfully"), HttpStatus.OK);
        else
            return new ResponseEntity<>(BaseResponse.error("Unable to update the specified pilot"), HttpStatus.INTERNAL_SERVER_ERROR);
    }

}
