package gr.atc.urbreath.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import gr.atc.urbreath.enums.PilotRole;
import gr.atc.urbreath.validation.ValidPassword;
import gr.atc.urbreath.validation.ValidPilotRole;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Null;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserDTO {

    @JsonProperty("userId")
    private String userId;

    @JsonProperty("username")
    private String username;

    @ValidPassword
    @JsonProperty("password")
    private String password;

    @JsonProperty("firstName")
    private String firstName;

    @JsonProperty("lastName")
    private String lastName;

    @Email
    @JsonProperty("email")
    private String email;

    @ValidPilotRole
    @JsonProperty("pilotRole")
    private PilotRole pilotRole;

    @JsonProperty("pilotCode")
    private String pilotCode;

    @Null
    @JsonProperty("activationToken")
    @JsonIgnore
    private String activationToken;

    @Null
    @JsonProperty("activationExpiry")
    @JsonIgnore
    private String activationExpiry;

    @Null
    @JsonProperty("resetToken")
    @JsonIgnore
    private String resetToken;

    @Null
    @JsonProperty("tokenFlag")
    @JsonIgnore
    private boolean tokenFlagRaised;
}
