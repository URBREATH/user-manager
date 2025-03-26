package gr.atc.urbreath.keycloak;

import java.io.IOException;

import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import gr.atc.urbreath.controller.BaseResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class
UnauthorizedEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");

        // Che
        String requestPath = request.getRequestURI();
        if (isExcludedPath(requestPath)) {
            return;
        }

        // Check the validity of the token
        String errorMessage = "Unauthorized request. Check token and try again.";
        String errorCode = "Invalid or missing Token";

        if (authException instanceof OAuth2AuthenticationException) {
            errorMessage = "Invalid JWT provided.";
            errorCode = "JWT has expired or is invalid";
        }

        BaseResponse<String> responseMessage = BaseResponse.error(errorMessage, errorCode);

        ObjectMapper mapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        mapper.writeValue(response.getWriter(), responseMessage);

        response.getWriter().flush();
    }

    private boolean isExcludedPath(String path) {
        // Define paths to exclude from unauthorized handling
        return path.equals("/api/users/refresh-token") ||
                path.equals("/api/users/authenticate") ||
                path.equals("/api/users/activate");
    }
}