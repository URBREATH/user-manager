package gr.atc.urbreath.dto.keycloak;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ClientRepresentationDTO {
    private String id;
    private String name;
    private String clientId;
    private boolean enabled;
}
