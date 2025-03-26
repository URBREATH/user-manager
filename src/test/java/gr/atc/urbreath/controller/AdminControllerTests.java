package gr.atc.urbreath.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.Matchers.is;

import gr.atc.urbreath.service.IAdminService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.when;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import gr.atc.urbreath.dto.PilotDTO;

@WebMvcTest(AdminController.class)
@EnableMethodSecurity(prePostEnabled = true)
class AdminControllerTests {

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private IAdminService adminService;

    @Autowired
    private ObjectMapper objectMapper;

    private Jwt superAdminJwt;
    private Jwt adminJwt;

    @BeforeEach
    void setup() {
        // Super Admin JWT
        superAdminJwt = createMockJwtToken("SUPER_ADMIN", "ALL");

        // Admin JWT
        adminJwt = createMockJwtToken("ADMIN", "ATHENS");
    }

    private Jwt createMockJwtToken(String pilotRole, String pilotCode) {
        String tokenValue = "mock.jwt.token";
        Map<String, Object> claims = new HashMap<>();
        claims.put("realm_access", Map.of("roles", List.of(pilotRole)));
        claims.put("resource_access", Map.of("urbreath", Map.of("roles", List.of(pilotRole))));
        claims.put("sub", "user");
        claims.put("pilot_code", pilotCode);
        claims.put("pilot_role", pilotRole);

        return Jwt.withTokenValue(tokenValue)
                .headers(header -> header.put("alg", "HS256"))
                .claims(claim -> claim.putAll(claims))
                .build();
    }

    private void mockJwtAuthentication(Jwt jwt, String authority) {
        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(
                jwt,
                List.of(new SimpleGrantedAuthority(authority))
        );
        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);
    }

    @DisplayName("Get All Pilot Codes: Success")
    @Test
    void givenValidJwt_whenGetAllPilotCodes_thenReturnPilotCodes() throws Exception {
        // Given
        List<String> pilotRoles = List.of("ATHENS");
        given(adminService.retrieveAllPilots(anyString())).willReturn(pilotRoles);

        // Mock JWT authentication
        mockJwtAuthentication(superAdminJwt, "ROLE_SUPER_ADMIN");

        // When
        ResultActions response = mockMvc.perform(get("/api/admin/pilots")
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("Pilot codes retrieved successfully")))
                .andExpect(jsonPath("$.data", is(pilotRoles)));
    }

    @DisplayName("Get All Pilot Codes: Forbidden for Admins")
    @Test
    void givenNonSuperAdminJwt_whenGetAllPilotCodes_thenReturnForbidden() throws Exception {
        // Mock JWT authentication
        mockJwtAuthentication(adminJwt, "ROLE_ADMIN");

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.get("/api/admin/pilots")
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isForbidden());
    }

    @DisplayName("Get All Pilot Roles: Success")
    @Test
    void givenValidJwt_whenGetAllPilotRoles_thenReturnPilotRoles() throws Exception {
        // Given
        List<String> pilotRoles = List.of("ADMIN", "SUPER_ADMIN");
        given(adminService.retrieveAllSystemRoles(anyString(), anyBoolean())).willReturn(pilotRoles);

        // Mock JWT authentication
        mockJwtAuthentication(superAdminJwt, "ROLE_SUPER_ADMIN");

        // When
        ResultActions response = mockMvc.perform(get("/api/admin/roles")
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("System roles retrieved successfully")))
                .andExpect(jsonPath("$.data", is(pilotRoles)));
    }

    @DisplayName("Create a new pilot: Success")
    @Test
    void givenPilotInformation_whenCreateNewPilotInSystem_thenReturnSuccess() throws Exception {
        // Given
        PilotDTO pilotData = PilotDTO.builder()
                .name("TEST_PILOT")
                .build();

        // Mock service method
        when(adminService.createPilot(anyString(), any(PilotDTO.class)))
                .thenReturn(true);

        // Mock JWT authentication
        mockJwtAuthentication(superAdminJwt, "ROLE_SUPER_ADMIN");

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.post("/api/admin/pilot")
                .with(csrf())
                .content(objectMapper.writeValueAsString(pilotData))
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isCreated())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("Pilot created successfully")));
    }

    @DisplayName("Update a pilot: Success")
    @Test
    void givenPilotInformation_whenUpdatePilotInSystem_thenReturnSuccess() throws Exception {
        // Given
        String pilotName = "TEST_PILOT";
        PilotDTO pilotData = PilotDTO.builder()
                .name(pilotName)
                .build();

        // Mock service method
        when(adminService.updatePilot(anyString(), anyString(), any(PilotDTO.class)))
                .thenReturn(true);

        // Mock JWT authentication
        mockJwtAuthentication(superAdminJwt, "ROLE_SUPER_ADMIN");

        // When
        ResultActions response = mockMvc.perform(put("/api/admin/pilot/{pilotName}", pilotName)
                .with(csrf())
                .content(objectMapper.writeValueAsString(pilotData))
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("Pilot updated successfully")));
    }

    @DisplayName("Delete a pilot: Success")
    @Test
    void givenPilotName_whenDeletePilotInSystem_thenReturnSuccess() throws Exception {
        // Given
        String pilotName = "TEST_PILOT";

        // Mock service method
        when(adminService.deletePilot(anyString(), anyString()))
                .thenReturn(true);

        // Mock JWT authentication
        mockJwtAuthentication(superAdminJwt, "ROLE_SUPER_ADMIN");

        // When
        ResultActions response = mockMvc.perform(delete("/api/admin/pilot/{pilotName}", pilotName)
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isOk())
                .andExpect(jsonPath("$.success", is(true)))
                .andExpect(jsonPath("$.message", is("Pilot deleted successfully")));
    }

    @DisplayName("Create a new pilot: Failure due to internal server error")
    @Test
    void givenPilotInformation_whenCreateNewPilotFails_thenReturnInternalServerError() throws Exception {
        // Given
        PilotDTO pilotData = PilotDTO.builder()
                .name("TEST_PILOT")
                .build();

        // Mock service method
        when(adminService.createPilot(anyString(), any(PilotDTO.class)))
                .thenReturn(false);

        // Mock JWT authentication
        mockJwtAuthentication(superAdminJwt, "ROLE_SUPER_ADMIN");

        // When
        ResultActions response = mockMvc.perform(MockMvcRequestBuilders.post("/api/admin/pilot")
                .with(csrf())
                .content(objectMapper.writeValueAsString(pilotData))
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.success", is(false)))
                .andExpect(jsonPath("$.message", is("Unable to create and store the new pilot")));
    }

    @DisplayName("Unauthorized Access: No Authentication")
    @Test
    void givenNoAuthentication_whenAccessAdminEndpoint_thenReturnUnauthorized() throws Exception {
        // When
        ResultActions response = mockMvc.perform(get("/api/admin/roles")
                .contentType(MediaType.APPLICATION_JSON));

        // Then
        response.andExpect(status().isUnauthorized());
    }
}
