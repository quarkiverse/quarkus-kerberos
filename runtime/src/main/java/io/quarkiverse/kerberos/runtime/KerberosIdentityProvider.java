package io.quarkiverse.kerberos.runtime;

import static javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.inject.Singleton;
import javax.security.auth.Subject;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.jboss.logging.Logger;

import io.quarkiverse.kerberos.GSSContextCredential;
import io.quarkiverse.kerberos.KerberosCallbackHandler;
import io.quarkiverse.kerberos.NegotiateAuthenticationRequest;
import io.quarkiverse.kerberos.ServicePrincipalSubjectFactory;
import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.security.AuthenticationCompletionException;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.HttpSecurityUtils;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

@Singleton
public class KerberosIdentityProvider implements IdentityProvider<NegotiateAuthenticationRequest> {

    private static final Logger LOG = Logger.getLogger(KerberosIdentityProvider.class);

    private static final String KRB5_LOGIN_MODULE = "com.sun.security.auth.module.Krb5LoginModule";
    private static final String KERBEROS_OID = "1.2.840.113554.1.2.2";
    private static final String SPNEGO_OID = "1.3.6.1.5.5.2";
    private static final String DEFAULT_LOGIN_CONTEXT_NAME = "KDC";

    private final Instance<KerberosCallbackHandler> callbackHandler;

    private final Instance<ServicePrincipalSubjectFactory> servicePrincipalSubjectFactory;

    private final KerberosConfig kerberosConfig;

    private final String realKeytabPath;

    @Inject
    public KerberosIdentityProvider(Instance<KerberosCallbackHandler> callbackHandler,
            Instance<ServicePrincipalSubjectFactory> servicePrincipalSubjectFactory, KerberosConfig kerberosConfig) {
        this.callbackHandler = callbackHandler;
        this.servicePrincipalSubjectFactory = servicePrincipalSubjectFactory;
        this.kerberosConfig = kerberosConfig;
        if (callbackHandler.isResolvable() && callbackHandler.isAmbiguous()) {
            throw new IllegalStateException("Multiple " + KerberosCallbackHandler.class + " beans registered");
        }
        if (servicePrincipalSubjectFactory.isResolvable() && servicePrincipalSubjectFactory.isAmbiguous()) {
            throw new IllegalStateException("Multiple " + ServicePrincipalSubjectFactory.class + " beans registered");
        }
        String realKeytabPath = null;
        if (kerberosConfig.keytabPath.isPresent()) {
            URL keytabUrl = Thread.currentThread().getContextClassLoader().getResource(kerberosConfig.keytabPath.get());
            if (keytabUrl != null) {
                realKeytabPath = keytabUrl.toString();
            } else {
                Path filePath = Paths.get(kerberosConfig.keytabPath.get());
                if (Files.exists(filePath)) {
                    realKeytabPath = filePath.toUri().toString();
                }
            }
            if (realKeytabPath == null) {
                throw new ConfigurationException("Keytab file is not available at " + kerberosConfig.keytabPath.get());
            }
        }
        this.realKeytabPath = realKeytabPath;
    }

    @Override
    public Class<NegotiateAuthenticationRequest> getRequestType() {
        return NegotiateAuthenticationRequest.class;
    }

    @Override
    public Uni<SecurityIdentity> authenticate(NegotiateAuthenticationRequest request, AuthenticationRequestContext context) {
        RoutingContext routingContext = HttpSecurityUtils.getRoutingContextAttribute(request);
        return context.runBlocking(new Supplier<SecurityIdentity>() {

            @Override
            public SecurityIdentity get() {
                try {
                    String completeServicePrincipalName = getCompleteServicePrincipalName(routingContext);
                    Subject serviceSubject = getSubjectForServicePrincipal(completeServicePrincipalName);
                    if (serviceSubject == null) {
                        LOG.debugf("Service Principal Subject is null");
                        throw new AuthenticationCompletionException();
                    }

                    GSSContext gssContext = createGSSContext(routingContext, completeServicePrincipalName);

                    String serviceTicket = request.getValue();

                    byte[] negotiationBytes = Subject.doAs(serviceSubject,
                            new ValidateServiceTicketAction(gssContext, Base64.getDecoder().decode(serviceTicket)));
                    if (negotiationBytes != null && negotiationBytes.length > 0) {
                        routingContext.put(KerberosAuthenticationMechanism.NEGOTIATE_DATA,
                                Base64.getEncoder().encodeToString(negotiationBytes));
                    }
                    if (gssContext.isEstablished()) {
                        GSSName srcName = gssContext.getSrcName();
                        if (srcName == null) {
                            LOG.debugf("GSS name is null");
                            throw new AuthenticationCompletionException();
                        }

                        GSSContextCredential gssContextCredential = new GSSContextCredential(gssContext);
                        return QuarkusSecurityIdentity.builder()
                                .addCredential(gssContextCredential)
                                .setPrincipal(new KerberosPrincipal(srcName))
                                .build();
                    } else {
                        if (negotiationBytes == null || negotiationBytes.length == 0) {
                            LOG.debugf("GSS context is not established but no more negotiation data is available");
                            throw new AuthenticationCompletionException();
                        }
                        LOG.debugf("Token %s is processed, continue to negotiate", serviceTicket);
                        // Trigger a new challenge
                        throw new AuthenticationFailedException();
                    }
                } catch (LoginException ex) {
                    LOG.debugf("Login exception: %s", ex.getMessage());
                    throw new RuntimeException(ex);
                } catch (GSSException ex) {
                    LOG.debugf("GSS exception: %s", ex.getMessage());
                    throw new AuthenticationFailedException(ex);
                } catch (PrivilegedActionException ex) {
                    LOG.debugf("PrivilegedAction exception: %s", ex.getMessage());
                    throw new RuntimeException(ex);
                }
            }

        });
    }

    protected Subject getSubjectForServicePrincipal(String completeServicePrincipalName) throws LoginException {

        if (servicePrincipalSubjectFactory.isResolvable()) {
            Subject subject = servicePrincipalSubjectFactory.get().getSubjectForServicePrincipal(completeServicePrincipalName);
            if (subject != null) {
                return subject;
            }
        }

        Configuration config = DEFAULT_LOGIN_CONTEXT_NAME.equals(kerberosConfig.loginContextName)
                ? new DefaultJAASConfiguration(completeServicePrincipalName)
                : null;
        final LoginContext lc = new LoginContext(kerberosConfig.loginContextName,
                new Subject(),
                // callback is not required if a keytab is used
                (callbackHandler.isResolvable() ? callbackHandler.get() : null),
                config);
        lc.login();
        return lc.getSubject();
    }

    protected GSSContext createGSSContext(RoutingContext routingContext, String completeServicePrincipalName)
            throws GSSException {
        Oid oid = new Oid(kerberosConfig.useSpnegoOid ? SPNEGO_OID : KERBEROS_OID);

        GSSManager gssManager = GSSManager.getInstance();

        GSSName gssService = gssManager.createName(completeServicePrincipalName, null);
        return gssManager.createContext(gssService.canonicalize(oid), oid, null, GSSContext.INDEFINITE_LIFETIME);
    }

    protected String getCompleteServicePrincipalName(RoutingContext routingContext) {
        String name = kerberosConfig.servicePrincipalName.isEmpty()
                ? "HTTP/" + routingContext.request().host()
                : kerberosConfig.servicePrincipalName.get();
        int portIndex = name.indexOf(":");
        if (portIndex > 0) {
            name = name.substring(0, portIndex);
        }
        if (kerberosConfig.servicePrincipalRealm.isPresent()) {
            name += "@" + kerberosConfig.servicePrincipalRealm.get();
        }
        return name;
    }

    static class KerberosPrincipal implements Principal {
        private String simpleName;
        private String complexName;

        public KerberosPrincipal(GSSName srcName) {
            this.complexName = srcName.toString();
            int index = complexName.lastIndexOf('@');
            simpleName = index > 0 ? complexName.substring(0, index) : complexName;
        }

        public String getGssSourceName() {
            return complexName;
        }

        @Override
        public String getName() {
            return simpleName;
        }
    }

    private static final class ValidateServiceTicketAction implements PrivilegedExceptionAction<byte[]> {
        private final GSSContext context;
        private final byte[] token;

        private ValidateServiceTicketAction(GSSContext context, byte[] token) {
            this.context = context;
            this.token = token;
        }

        public byte[] run() throws GSSException {
            return context.acceptSecContext(token, 0, token.length);
        }
    }

    private class DefaultJAASConfiguration extends Configuration {
        String completeServicePrincipalName;

        public DefaultJAASConfiguration(String completeServicePrincipalName) {
            this.completeServicePrincipalName = completeServicePrincipalName;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            if (!DEFAULT_LOGIN_CONTEXT_NAME.equals(name)) {
                throw new IllegalArgumentException("Unexpected name '" + name + "'");
            }

            AppConfigurationEntry[] entries = new AppConfigurationEntry[1];
            Map<String, Object> options = new HashMap<>();
            if (kerberosConfig.debug) {
                options.put("debug", "true");
            }
            options.put("refreshKrb5Config", "true");
            options.put("storeKey", "true");
            options.put("isInitiator", "true");
            if (realKeytabPath != null) {
                options.put("useKeyTab", "true");
                options.put("keyTab", realKeytabPath);
                options.put("principal", completeServicePrincipalName);
            }
            entries[0] = new AppConfigurationEntry(KRB5_LOGIN_MODULE, REQUIRED, options);

            return entries;
        }

    }
}
