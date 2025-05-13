package com.cloudiam.keycloak.anonymous;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.utils.MediaType;

public class AnonymousGrantTypeProvider implements RealmResourceProvider {

    private static final Logger LOGGER = Logger.getLogger(AnonymousGrantTypeProvider.class);
    public static final String ANONYMOUS_GRANT_TYPE = "anonymous";
    private final KeycloakSession session;


    public AnonymousGrantTypeProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response token(MultivaluedMap<String, String> formParams) {
        LOGGER.info("Custom token endpoint invoked");
        String grantType = formParams.getFirst("grant_type");

        if ("anonymous".equals(grantType)) {
            return handleAnonymousGrant(formParams);
        }

        return delegateToDefaultImplementation(formParams);
    }

    private Response handleAnonymousGrant(MultivaluedMap<String, String> formParams) {
        LOGGER.info("Handling anonymous grant type");
        return Response.ok().entity("Anonymous grant type handled").build();
    }

    private Response delegateToDefaultImplementation(MultivaluedMap<String, String> formParams) {
        return Response.status(Response.Status.NOT_IMPLEMENTED)
                .entity("Default grant types not implemented in this example")
                .build();
    }

    @Override
    public void close() {
        LOGGER.info("******** CLOSING ANONYMOUS GRANT TYPE PROVIDER ********");
        session.close();
    }
}
