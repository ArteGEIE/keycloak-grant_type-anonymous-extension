package com.cloudiam.keycloak.anonymous;

import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;

public class AnonymousGrantTypeProvider implements OAuth2GrantType {
    private static final Logger LOGGER = Logger.getLogger(AnonymousGrantTypeProvider.class);
    
    public static final String GRANT_TYPE = "anonymous";
    private final KeycloakSession session;

    public AnonymousGrantTypeProvider(KeycloakSession session) {
        this.session = session;
        LOGGER.info("AnonymousGrantTypeProvider initialized");
    }


    @Override
    public void close() {
        LOGGER.info("******** CLOSING ANONYMOUS GRANT TYPE PROVIDER ********");
        session.close();
    }

    @Override
    public EventType getEventType() {
        return null;
    }

    @Override
    public Response process(Context context) {
        return null;
    }
}
