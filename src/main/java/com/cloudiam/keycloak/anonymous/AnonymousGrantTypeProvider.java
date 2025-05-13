package com.cloudiam.keycloak.anonymous;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.events.EventType;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;

public class AnonymousGrantTypeProvider implements OAuth2GrantType {

    private static final Logger LOGGER = Logger.getLogger(AnonymousGrantTypeProvider.class);

    @Override
    public EventType getEventType() {
        return null;
    }

    @Override
    public Response process(Context context) {
        return null;
    }

    @Override
    public void close() {

    }
}
