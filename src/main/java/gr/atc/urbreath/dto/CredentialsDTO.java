package gr.atc.urbreath.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import gr.atc.urbreath.validation.ValidPassword;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CredentialsDTO {

    @Email(message = "Email is not valid")
    @NotEmpty(message = "Email is required")
    @JsonProperty("email")
    private String email;

    @ValidPassword
    @NotEmpty(message = "Password is required")
    @JsonProperty("password")
    private String password;

}
