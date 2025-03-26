package gr.atc.urbreath.service;

import gr.atc.urbreath.dto.PilotDTO;
import gr.atc.urbreath.dto.keycloak.GroupRepresentationDTO;

import java.util.List;

public interface IAdminService {

    List<String> retrieveAllSystemRoles(String token, boolean isSuperAdmin);

    List<String> retrieveAllPilots(String token);

    boolean createPilot(String token, PilotDTO pilotData);

    boolean deletePilot(String token, String pilotName);

    boolean updatePilot(String token, String pilotName, PilotDTO pilotData);

    GroupRepresentationDTO retrievePilot(String token, String pilotName);
}

