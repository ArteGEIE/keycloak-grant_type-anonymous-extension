package com.cloudiam.keycloak.anonymous;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeFactory;

public class AnonymousGrantTypeFactory implements OAuth2GrantTypeFactory {
    private static final Logger logger = Logger.getLogger(AnonymousGrantTypeFactory.class);
    public static final String PROVIDER_ID = "anonymous";

    @Override
    public OAuth2GrantType create(KeycloakSession session) {
        return new AnonymousGrantType(session);
    }

    @Override
    public void init(Config.Scope config) {
        logger.info("******** INITIALIZING ANONYMOUS GRANT TYPE FACTORY ********");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        logger.info("******** POST INIT ANONYMOUS GRANT TYPE FACTORY ********");
    }

    @Override
    public void close() {
        logger.info("******** CLOSING ANONYMOUS GRANT TYPE FACTORY ********");
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public int order() {
        return 100;
    }
}
