package gr.atc.urbreath.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import gr.atc.urbreath.validation.ValidPassword;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class PasswordDTO {

    @ValidPassword
    @NotEmpty(message = "Current password is required")
    @JsonProperty("currentPassword")
    private String currentPassword;

    @ValidPassword
    @NotEmpty(message = "New password is required")
    @JsonProperty("newPassword")
    private String newPassword;
}
