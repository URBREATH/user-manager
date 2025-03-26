package gr.atc.urbreath.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import gr.atc.urbreath.controller.BaseResponse;
import gr.atc.urbreath.util.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

public class JwtAttributesValidatorFilter extends GenericFilterBean {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (SecurityContextHolder.getContext().getAuthentication() instanceof JwtAuthenticationToken jwtToken) {
            Jwt jwt = jwtToken.getToken();

            // Extract required fields
            String role = JwtUtils.extractPilotRole(jwt);
            String pilotCode = JwtUtils.extractPilotCode(jwt);

            // Validate presence of required claims
            if (isEmpty(role) || isEmpty(pilotCode)) {
                HttpServletResponse httpResponse = (HttpServletResponse) response;

                // Headers
                httpResponse.setStatus(HttpStatus.FORBIDDEN.value());
                httpResponse.setContentType("application/json");
                httpResponse.setCharacterEncoding("UTF-8");

                // Response
                BaseResponse<String> responseMessage = BaseResponse.error("Invalid JWT Token Attributes", "Some information regarding Pilot Code and Role are missing from the token");
                ObjectMapper mapper = new ObjectMapper();
                mapper.registerModule(new JavaTimeModule());
                String jsonResponse = mapper.writeValueAsString(responseMessage);

                httpResponse.getWriter().write(jsonResponse);
                httpResponse.getWriter().flush();
                return;
            }
        }

        chain.doFilter(request, response);
    }

    private boolean isEmpty(String value) {
        return value == null || value.trim().isEmpty();
    }
}
