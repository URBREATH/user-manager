package gr.atc.urbreath.service;

import gr.atc.urbreath.dto.keycloak.ClientRepresentationDTO;
import gr.atc.urbreath.dto.keycloak.GroupRepresentationDTO;
import gr.atc.urbreath.exception.CustomExceptions.DataRetrievalException;
import gr.atc.urbreath.exception.CustomExceptions.KeycloakException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class KeycloakSupportServiceTests {

    @Mock
    private RestTemplate restTemplate;

    @InjectMocks
    private KeycloakSupportService keycloakSupportService;

    private static final String MOCK_TOKEN = "mock-token";
    private static final String MOCK_ADMIN_URI = "http://mock-admin-uri";
    private static final String MOCK_TOKEN_URI = "http://mock-token-uri";
    private static final String MOCK_CLIENT_ID = "mock-client";
    private static final String MOCK_CLIENT_SECRET = "client-secret";
    private static final String MOCK_CLIENT_UUID = "client-uuid-123";
    private static final String MOCK_GROUP_ID = "group-id-123";
    private static final String TOKEN = "access_token";

    @BeforeEach
    void setup() {
        ReflectionTestUtils.setField(keycloakSupportService, "tokenUri", MOCK_TOKEN_URI);
        ReflectionTestUtils.setField(keycloakSupportService, "adminUri", MOCK_ADMIN_URI);
        ReflectionTestUtils.setField(keycloakSupportService, "clientId", MOCK_CLIENT_ID);
        ReflectionTestUtils.setField(keycloakSupportService, "clientSecret", MOCK_CLIENT_SECRET);
        ReflectionTestUtils.setField(keycloakSupportService, "restTemplate", restTemplate);
    }

    @AfterEach
    void tearDown() {
        reset(restTemplate);
    }

    @Test
    @DisplayName("Retrieve JWT token - Success")
    void retrieveComponentJwtToken_Success_ReturnsToken() {
        Map<String, Object> responseBody = Map.of(TOKEN, MOCK_TOKEN);
        ResponseEntity<Map<String, Object>> mockResponse = ResponseEntity.ok(responseBody);

        when(restTemplate.exchange(
                eq(MOCK_TOKEN_URI),
                eq(HttpMethod.POST),
                any(),
                any(ParameterizedTypeReference.class))
        ).thenReturn(mockResponse);

        String result = keycloakSupportService.retrieveComponentJwtToken();
        assertEquals(MOCK_TOKEN, result);
    }

    @Test
    @DisplayName("Retrieve JWT token - Empty Response Body")
    void retrieveComponentJwtToken_EmptyBody_ReturnsNull() {
        ResponseEntity<Map<String, Object>> mockResponse = ResponseEntity.ok(null);

        when(restTemplate.exchange(
                eq(MOCK_TOKEN_URI),
                eq(HttpMethod.POST),
                any(),
                any(ParameterizedTypeReference.class))
        ).thenReturn(mockResponse);

        assertNull(keycloakSupportService.retrieveComponentJwtToken());
    }

    @Test
    @DisplayName("Retrieve JWT token - HTTP Error")
    void retrieveComponentJwtToken_HttpError_ReturnsNull() {
        when(restTemplate.exchange(
                eq(MOCK_TOKEN_URI),
                eq(HttpMethod.POST),
                any(),
                any(ParameterizedTypeReference.class))
        ).thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST));

        assertNull(keycloakSupportService.retrieveComponentJwtToken());
    }

    @Test
    @DisplayName("Retrieve Client ID - Success")
    void retrieveClientId_Success_ReturnsClientId() {
        ClientRepresentationDTO client = new ClientRepresentationDTO();
        client.setClientId(MOCK_CLIENT_ID);
        client.setId(MOCK_CLIENT_UUID);
        ResponseEntity<List<ClientRepresentationDTO>> mockResponse = ResponseEntity.ok(List.of(client));

        when(restTemplate.exchange(
                eq(MOCK_ADMIN_URI + "/clients"),
                eq(HttpMethod.GET),
                any(),
                any(ParameterizedTypeReference.class))
        ).thenReturn(mockResponse);

        String result = keycloakSupportService.retrieveClientId(MOCK_TOKEN, MOCK_CLIENT_ID);
        assertEquals(MOCK_CLIENT_UUID, result);
    }

    @Test
    @DisplayName("Retrieve Client ID - Client Not Found")
    void retrieveClientId_ClientNotFound_ThrowsException() {
        ResponseEntity<List<ClientRepresentationDTO>> mockResponse = ResponseEntity.ok(Collections.emptyList());

        when(restTemplate.exchange(
                eq(MOCK_ADMIN_URI + "/clients"),
                eq(HttpMethod.GET),
                any(),
                any(ParameterizedTypeReference.class))
        ).thenReturn(mockResponse);

        assertThrows(DataRetrievalException.class, () ->
                keycloakSupportService.retrieveClientId(MOCK_TOKEN, MOCK_CLIENT_ID));
    }

    @Test
    @DisplayName("Retrieve Client ID - HTTP Server Error")
    void retrieveClientId_HttpServerError_ThrowsKeycloakException() {
        when(restTemplate.exchange(
                eq(MOCK_ADMIN_URI + "/clients"),
                eq(HttpMethod.GET),
                any(),
                any(ParameterizedTypeReference.class))
        ).thenThrow(new HttpServerErrorException(HttpStatus.INTERNAL_SERVER_ERROR));

        assertThrows(KeycloakException.class, () ->
                keycloakSupportService.retrieveClientId(MOCK_TOKEN, MOCK_CLIENT_ID));
    }

    @Test
    @DisplayName("Retrieve Pilot Code ID - Success")
    void retrievePilotCodeID_Success_ReturnsGroupId() {
        GroupRepresentationDTO group = new GroupRepresentationDTO();
        group.setName("testPilot");
        group.setId(MOCK_GROUP_ID);
        ResponseEntity<List<GroupRepresentationDTO>> mockResponse = ResponseEntity.ok(List.of(group));

        when(restTemplate.exchange(
                eq(MOCK_ADMIN_URI + "/groups"),
                eq(HttpMethod.GET),
                any(),
                any(ParameterizedTypeReference.class))
        ).thenReturn(mockResponse);

        String result = keycloakSupportService.retrievePilotCodeID(MOCK_TOKEN, "testPilot");
        assertEquals(MOCK_GROUP_ID, result);
    }

    @Test
    @DisplayName("Retrieve Pilot Code ID - Group Not Found")
    void retrievePilotCodeID_GroupNotFound_ReturnsNull() {
        ResponseEntity<List<GroupRepresentationDTO>> mockResponse = ResponseEntity.ok(Collections.emptyList());

        when(restTemplate.exchange(
                eq(MOCK_ADMIN_URI + "/groups"),
                eq(HttpMethod.GET),
                any(),
                any(ParameterizedTypeReference.class))
        ).thenReturn(mockResponse);

        assertNull(keycloakSupportService.retrievePilotCodeID(MOCK_TOKEN, "nonExistingPilot"));
    }

    @Test
    @DisplayName("Retrieve Pilot Code ID - Rest Client Exception")
    void retrievePilotCodeID_RestClientException_ThrowsException() {
        when(restTemplate.exchange(
                eq(MOCK_ADMIN_URI + "/groups"),
                eq(HttpMethod.GET),
                any(),
                any(ParameterizedTypeReference.class))
        ).thenThrow(new RestClientException("Connection failed"));

        assertThrows(DataRetrievalException.class, () ->
                keycloakSupportService.retrievePilotCodeID(MOCK_TOKEN, "testPilot"));
    }

    @Test
    @DisplayName("Init Method - Initializes CachedClientId")
    void init_WhenCalled_SetsCachedClientId() {
        // Mock token retrieval
        Map<String, Object> tokenResponse = Map.of(TOKEN, MOCK_TOKEN);
        when(restTemplate.exchange(
                eq(MOCK_TOKEN_URI),
                eq(HttpMethod.POST),
                any(),
                any(ParameterizedTypeReference.class))
        ).thenReturn(ResponseEntity.ok(tokenResponse));

        // Mock client retrieval
        ClientRepresentationDTO client = new ClientRepresentationDTO();
        client.setClientId(MOCK_CLIENT_ID);
        client.setId(MOCK_CLIENT_UUID);
        when(restTemplate.exchange(
                eq(MOCK_ADMIN_URI + "/clients"),
                eq(HttpMethod.GET),
                any(),
                any(ParameterizedTypeReference.class))
        ).thenReturn(ResponseEntity.ok(List.of(client)));

        keycloakSupportService.init();

        String cachedClientId = (String) ReflectionTestUtils.getField(keycloakSupportService, "cachedClientId");
        assertEquals(MOCK_CLIENT_UUID, cachedClientId);
    }

    @Test
    @DisplayName("Get Client ID - Returns Cached Value")
    void getClientId_WhenCached_ReturnsCachedValue() {
        ReflectionTestUtils.setField(keycloakSupportService, "cachedClientId", MOCK_CLIENT_UUID);
        assertEquals(MOCK_CLIENT_UUID, keycloakSupportService.getClientId());
    }
}