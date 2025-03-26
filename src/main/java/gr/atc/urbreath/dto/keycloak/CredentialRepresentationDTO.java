package gr.atc.urbreath.dto.keycloak;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CredentialRepresentationDTO {

    @JsonProperty("temporary")
    private boolean temporary;

    @JsonProperty("type")
    private String type;

    @JsonProperty("value")
    private String value;
}
