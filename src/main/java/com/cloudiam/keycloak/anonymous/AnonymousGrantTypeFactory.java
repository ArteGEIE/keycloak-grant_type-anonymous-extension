package com.cloudiam.keycloak.anonymous;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeFactory;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;

public class AnonymousGrantTypeFactory implements OAuth2GrantTypeFactory {
    private static final Logger logger = Logger.getLogger(AnonymousGrantTypeFactory.class);
    public static final String PROVIDER_ID = "anonymous-grant-type";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public OAuth2GrantType create(KeycloakSession session) {
        return null;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
