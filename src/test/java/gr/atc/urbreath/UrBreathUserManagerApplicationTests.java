package gr.atc.urbreath;

import gr.atc.urbreath.service.KeycloakSupportService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest
class UrBreathUserManagerApplicationTests {

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private KeycloakSupportService keycloakSupportService;

    @Test
    void contextLoads() {
        Assertions.assertNotNull(ApplicationContext.class);
    }

}
