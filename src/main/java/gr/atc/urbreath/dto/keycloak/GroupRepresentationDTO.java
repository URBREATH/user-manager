package gr.atc.urbreath.dto.keycloak;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class GroupRepresentationDTO {
    private String id;
    private String name;
    private String path;
    private List<GroupRepresentationDTO> subGroups;
}
