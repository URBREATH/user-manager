package gr.atc.urbreath.dto.keycloak;

import java.util.List;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RoleRepresentationDTO {

    private String id;

    private String name;

    private String description;

    private boolean composite;

    private boolean clientRole;

    private String containerId; // This is the Realm ID

    private Map<String, List<String>> attributes;
}
