package com.cloudiam.keycloak.anonymous;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class AnonymousGrantTypeFactory implements RealmResourceProviderFactory {
    private static final Logger logger = Logger.getLogger(AnonymousGrantTypeFactory.class);
    public static final String PROVIDER_ID = "default";

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new AnonymousGrantTypeProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        logger.info("******** INITIALIZING ANONYMOUS GRANT TYPE PROVIDER ********");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {
        logger.info("******** CLOSING ANONYMOUS GRANT TYPE PROVIDER ********");
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }



}
