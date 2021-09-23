package io.quarkiverse.kerberos.runtime;

import java.util.Collections;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;

import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkiverse.kerberos.NegotiateAuthenticationRequest;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport;
import io.quarkus.vertx.http.runtime.security.HttpSecurityUtils;
import io.smallrye.mutiny.Uni;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;

@ApplicationScoped
public class KerberosAuthenticationMechanism implements HttpAuthenticationMechanism {

    // KerberosIdentityProvider will set this RoutingContext attribute if GSSAPI context
    // will not be established and there will be more negotiate data to return to the client.
    static final String NEGOTIATE_DATA = "negotiate-data";

    private static final String NEGOTIATE_SCHEME = "Negotiate";

    private static final ChallengeData INITIAL_UNAUTHORIZED_CHALLENGE = new ChallengeData(
            HttpResponseStatus.UNAUTHORIZED.code(),
            HttpHeaderNames.WWW_AUTHENTICATE, NEGOTIATE_SCHEME);

    @Override
    public Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager identityProviderManager) {
        String negotiateToken = extractNegotiateToken(context);
        if (negotiateToken != null) {
            return identityProviderManager.authenticate(HttpSecurityUtils.setRoutingContextAttribute(
                    new NegotiateAuthenticationRequest(negotiateToken), context)).map(s -> {
                        if (context.get(NEGOTIATE_DATA) != null) {
                            context.response().headers().add(HttpHeaderNames.WWW_AUTHENTICATE,
                                    NEGOTIATE_SCHEME + " " + context.get(NEGOTIATE_DATA));
                        }
                        return s;
                    });
        }

        return Uni.createFrom().nullItem();
    }

    @Override
    public Uni<ChallengeData> getChallenge(RoutingContext context) {
        String base64EncodedNegotiateData = context.get(NEGOTIATE_DATA);
        if (base64EncodedNegotiateData != null) {
            return Uni.createFrom().item(new ChallengeData(HttpResponseStatus.UNAUTHORIZED.code(),
                    HttpHeaderNames.WWW_AUTHENTICATE, NEGOTIATE_SCHEME + " " + base64EncodedNegotiateData));
        } else {
            return Uni.createFrom().item(INITIAL_UNAUTHORIZED_CHALLENGE);
        }
    }

    @Override
    public Set<Class<? extends AuthenticationRequest>> getCredentialTypes() {
        // The service ticket can be viewed as an Spnego token.
        // TODO: However it will be easier to deal with a Negotiate specific request object.
        return Collections.singleton(NegotiateAuthenticationRequest.class);
    }

    @Override
    public HttpCredentialTransport getCredentialTransport() {
        return new HttpCredentialTransport(HttpCredentialTransport.Type.AUTHORIZATION, NEGOTIATE_SCHEME);
    }

    private String extractNegotiateToken(RoutingContext context) {
        final HttpServerRequest request = context.request();
        final String headerValue = request.headers().get(HttpHeaders.AUTHORIZATION.toString());

        if (headerValue == null) {
            return null;
        }

        int idx = headerValue.indexOf(' ');
        final String scheme = idx > 0 ? headerValue.substring(0, idx) : null;

        if (scheme == null || !NEGOTIATE_SCHEME.equals(scheme)) {
            return null;
        }

        return headerValue.substring(idx + 1);
    }
}
