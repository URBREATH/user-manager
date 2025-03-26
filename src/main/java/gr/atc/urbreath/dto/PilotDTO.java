package gr.atc.urbreath.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import gr.atc.urbreath.enums.PilotRole;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class PilotDTO {

    @NotEmpty(message = "Pilot code cannot be empty")
    @JsonProperty("name")
    private String name;
}
