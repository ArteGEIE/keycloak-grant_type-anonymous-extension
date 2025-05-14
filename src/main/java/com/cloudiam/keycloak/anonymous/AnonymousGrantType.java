package com.cloudiam.keycloak.anonymous;

import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;

public class AnonymousGrantType implements OAuth2GrantType {
    private static final Logger LOGGER = Logger.getLogger(AnonymousGrantType.class);
    private final KeycloakSession session;

    public AnonymousGrantType(KeycloakSession session) {
        this.session = session;
        LOGGER.info("******** ANONYMOUS GRANT TYPE PROVIDER INITIALIZED ********");
    }


    @Override
    public void close() {
        LOGGER.info("******** CLOSING ANONYMOUS GRANT TYPE PROVIDER ********");
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
