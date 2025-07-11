package com.cloudiam.keycloak.anonymous;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.common.util.reflections.Reflections;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.models.light.LightweightUserAdapter;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.TokenManager.AccessTokenResponseBuilder;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeBase;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.Urls;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.util.TokenUtil;

import java.lang.reflect.Field;
import java.util.UUID;

public class AnonymousGrantType extends OAuth2GrantTypeBase {

    private static final Logger LOGGER = Logger.getLogger(AnonymousGrantType.class);
    public static final String ANONYMOUS = "anonymous";
    private final KeycloakSession session;

    public AnonymousGrantType(KeycloakSession session) {
        this.session = session;
        LOGGER.debug("******** ANONYMOUS GRANT TYPE PROVIDER INITIALIZED ********");
    }


    @Override
    public void close() {
        LOGGER.debug("******** CLOSING ANONYMOUS GRANT TYPE PROVIDER ********");
    }

    @Override
    public EventType getEventType() {
        return EventType.LOGIN;
    }

    @Override
    public Response process(Context context) {
        setContext(context);
        event.detail(Details.AUTH_METHOD, ANONYMOUS);

        UserModel transientUser = createTransientUser();
        event.event(EventType.LOGIN);

        UserSessionProvider userSessionProvider = session.getProvider(UserSessionProvider.class);
        UserSessionModel userSession = userSessionProvider.createUserSession(
            UUID.randomUUID().toString(),
            realm,
            transientUser,
            transientUser.getUsername(),
            session.getContext().getConnection().getRemoteAddr(),
                ANONYMOUS,
            false,
            null,
            null,
            UserSessionModel.SessionPersistenceState.TRANSIENT
        );

        AuthenticatedClientSessionModel clientSession = session.sessions().createClientSession(realm, client, userSession);
        clientSession.setNote(OIDCLoginProtocol.ISSUER, Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        ClientSessionContext clientSessionCtx = DefaultClientSessionContext.fromClientSessionAndScopeParameter(
            clientSession, ANONYMOUS, session
        );

        LOGGER.info("******* ANONYMOUS GRANT TYPE START TOKEN GENERATION *******");

        TokenManager tokenManager = new TokenManager();
        // Create token response builder
        AccessTokenResponseBuilder tokenResponseBuilder = tokenManager
                .responseBuilder(realm, client, event, session, userSession, clientSessionCtx)
                .generateAccessToken();

        AccessTokenResponse tokenResponse = build(tokenResponseBuilder, userSession, clientSessionCtx);


        event.detail(Details.TOKEN_ID, tokenResponseBuilder.getAccessToken().getId());
        event.success();

        LOGGER.trace("******* ANONYMOUS GRANT TYPE TOKEN GENERATED SUCCESSFULLY *******");
        return cors.add(Response.ok(tokenResponse).type(MediaType.APPLICATION_JSON_TYPE));
    }

    public AccessTokenResponse build(AccessTokenResponseBuilder tokenResponseBuilder, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        AccessTokenResponse res = new AccessTokenResponse();
        AccessToken accessToken = tokenResponseBuilder.getAccessToken();


        if (accessToken != null) {
            event.detail(Details.TOKEN_ID, accessToken.getId());
            accessToken.setOtherClaims(ANONYMOUS, "true");

            String encodedToken = session.tokens().encode(accessToken);
            res.setToken(encodedToken);
            res.setTokenType(formatTokenType(client));
            if (accessToken.getExp() != 0) {
                res.setExpiresIn(accessToken.getExp() - Time.currentTime());
            }
        }

        int notBefore = realm.getNotBefore();
        if (client.getNotBefore() > notBefore) {
            notBefore = client.getNotBefore();
        }
        res.setNotBeforePolicy(notBefore);

        res = tokenManager.transformAccessTokenResponse(session, res, userSession, clientSessionCtx);

        // OIDC Financial API Read Only Profile : scope MUST be returned in the response from Token Endpoint
        String responseScope = clientSessionCtx.getScopeString();
        res.setScope(responseScope);
        event.detail(Details.SCOPE, responseScope);

        return res;
    }

    private String formatTokenType(ClientModel client) {
        if (OIDCAdvancedConfigWrapper.fromClientModel(client).isUseLowerCaseInTokenResponse()) {
            return TokenUtil.TOKEN_TYPE_BEARER.toLowerCase();
        }
        return TokenUtil.TOKEN_TYPE_BEARER;
    }

    private UserModel createTransientUser() {
        String id = UUID.randomUUID().toString();
        UserModel user = new LightweightUserAdapter(session, id);

        // Reflection to set up realm of the user, is fixed in 26.1.0 with new LightweightUserAdapter(session, realm, id);
        Field field = Reflections.findDeclaredField(user.getClass(), "realm");
        if (field != null) {
            field.setAccessible(true);
            try {
                field.set(user, realm);
            } catch (IllegalAccessException e) {
                LOGGER.error("Fail to set realm on the user", e);
                throw new IllegalArgumentException("Fail to set realm on the user", e);
            }
        }
        user.setUsername("anon-" + id);
        user.setEnabled(true);
        user.setSingleAttribute(ANONYMOUS, "true");

        return user;
    }

}
