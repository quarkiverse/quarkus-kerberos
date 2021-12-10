package io.quarkiverse.kerberos.client;

import static javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
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

import io.quarkus.runtime.configuration.ConfigurationException;

@ApplicationScoped
public class KerberosClientSupport {
    private static final Logger LOG = Logger.getLogger(KerberosClientSupport.class);

    private static final String KRB5_LOGIN_MODULE = "com.sun.security.auth.module.Krb5LoginModule";

    // See http://oid-info.com/get/1.2.840.113554.1.2.2
    private static final String KERBEROS_OID = "1.2.840.113554.1.2.2";
    // See http://oid-info.com/get/1.3.6.1.5.5.2
    private static final String SPNEGO_OID = "1.3.6.1.5.5.2";

    private static final String DEFAULT_LOGIN_CONTEXT_NAME = "KDC";

    private final Instance<KerberosCallbackHandler> callbackHandler;

    private final Instance<UserPrincipalSubjectFactory> userPrincipalSubjectFactory;

    private final KerberosClientConfig kerberosConfig;

    private final String realKeytabPath;

    @Inject
    public KerberosClientSupport(Instance<KerberosCallbackHandler> callbackHandler,
            Instance<UserPrincipalSubjectFactory> userPrincipalSubjectFactory, KerberosClientConfig kerberosConfig) {
        this.callbackHandler = callbackHandler;
        this.userPrincipalSubjectFactory = userPrincipalSubjectFactory;
        this.kerberosConfig = kerberosConfig;
        if (callbackHandler.isResolvable() && callbackHandler.isAmbiguous()) {
            throw new IllegalStateException("Multiple " + KerberosCallbackHandler.class + " beans registered");
        }
        if (userPrincipalSubjectFactory.isResolvable() && userPrincipalSubjectFactory.isAmbiguous()) {
            throw new IllegalStateException("Multiple " + UserPrincipalSubjectFactory.class + " beans registered");
        }
        String realKeytabPath = null;
        if (kerberosConfig.keytabPath().isPresent()) {
            URL keytabUrl = Thread.currentThread().getContextClassLoader().getResource(kerberosConfig.keytabPath().get());
            if (keytabUrl != null) {
                realKeytabPath = keytabUrl.toString();
            } else {
                Path filePath = Paths.get(kerberosConfig.keytabPath().get());
                if (Files.exists(filePath)) {
                    realKeytabPath = filePath.toAbsolutePath().toString();
                }
            }
            if (realKeytabPath == null) {
                throw new ConfigurationException("Keytab file is not available at " + kerberosConfig.keytabPath().get());
            }
        }
        this.realKeytabPath = realKeytabPath;
    }

    public String getServiceTicket() {
        return getServiceTicket(getCompleteUserPrincipalName());
    }

    public String getServiceTicket(String completeUserPrincipalName) {
        try {
            Subject userPrincipalSubject = getUserPrincipalSubject(completeUserPrincipalName);
            if (userPrincipalSubject == null) {
                LOG.debug("User Principal Subject is null");
                throw new RuntimeException();
            }
            return getServiceTicket(userPrincipalSubject);
        } catch (LoginException ex) {
            LOG.debugf("Login exception: %s", ex.getMessage());
            throw new RuntimeException(ex);
        }
    }

    public String getServiceTicket(Subject userPrincipalSubject) {
        try {
            return Subject.doAs(userPrincipalSubject, new PrivilegedExceptionAction<String>() {
                @Override
                public String run() throws Exception {
                    GSSContext context = createServiceContext();
                    return getNegotiateToken(context, new byte[0]);
                }
            });
        } catch (PrivilegedActionException ex) {
            Throwable ex2 = ex.getCause() != null ? ex.getCause() : ex;
            LOG.debugf("PrivilegedAction failure: %s", ex2.getMessage());
            throw new RuntimeException(ex);
        } catch (Throwable ex) {
            Throwable ex2 = ex.getCause() != null ? ex.getCause() : ex;
            LOG.debugf("Authentication failure: %s", ex2.getMessage());
            throw new RuntimeException(ex2);
        }
    }

    public Subject getUserPrincipalSubject() throws LoginException {
        return getUserPrincipalSubject(getCompleteUserPrincipalName());
    }

    public Subject getUserPrincipalSubject(String completeUserPrincipalName) throws LoginException {

        if (userPrincipalSubjectFactory.isResolvable()) {
            Subject subject = userPrincipalSubjectFactory.get().getSubjectForUserPrincipal(completeUserPrincipalName);
            if (subject != null) {
                return subject;
            }
        }
        String loginContextName = kerberosConfig.loginContextName().orElse(DEFAULT_LOGIN_CONTEXT_NAME);
        Configuration config = DEFAULT_LOGIN_CONTEXT_NAME.equals(loginContextName)
                ? new DefaultJAASConfiguration(completeUserPrincipalName)
                : null;
        final LoginContext lc = new LoginContext(loginContextName,
                new Subject(),
                // callback is not required if a keytab is used
                getCallback(completeUserPrincipalName),
                config);
        lc.login();
        return lc.getSubject();
    }

    public GSSContext createServiceContext() throws GSSException {
        Oid oid = new Oid(kerberosConfig.useSpnegoOid() ? SPNEGO_OID : KERBEROS_OID);
        GSSManager gssManager = GSSManager.getInstance();
        GSSName serverName = gssManager.createName(kerberosConfig.servicePrincipalName(), null);
        return gssManager.createContext(serverName, oid, null, GSSContext.DEFAULT_LIFETIME);
    }

    public String getNegotiateToken(GSSContext context, byte[] token) throws GSSException {
        token = context.initSecContext(token, 0, token.length);
        return Base64.getEncoder().encodeToString(token);
    }

    protected CallbackHandler getCallback(String completeUserPrincipalName) {
        if (callbackHandler.isResolvable()) {
            return callbackHandler.get();
        }
        if (kerberosConfig.userPrincipalPassword().isPresent()) {
            return new UsernamePasswordCBH(completeUserPrincipalName,
                    kerberosConfig.userPrincipalPassword().get().toCharArray());
        }
        return null;
    }

    private class DefaultJAASConfiguration extends Configuration {
        String completeUserPrincipalName;

        public DefaultJAASConfiguration(String completeUserPrincipalName) {
            this.completeUserPrincipalName = completeUserPrincipalName;
        }

        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            if (!DEFAULT_LOGIN_CONTEXT_NAME.equals(name)) {
                throw new IllegalArgumentException("Unexpected name '" + name + "'");
            }
            // See https://docs.oracle.com/javase/8/docs/jre/api/security/jaas/spec/com/sun/security/auth/module/Krb5LoginModule.html
            AppConfigurationEntry[] entries = new AppConfigurationEntry[1];
            Map<String, Object> options = new HashMap<>();
            if (kerberosConfig.debug()) {
                options.put("debug", "true");
            }
            options.put("refreshKrb5Config", "true");
            options.put("storeKey", "true");
            options.put("isInitiator", "true");
            if (realKeytabPath != null) {
                options.put("useKeyTab", "true");
                options.put("keyTab", realKeytabPath);
                options.put("principal", completeUserPrincipalName);
            }
            entries[0] = new AppConfigurationEntry(KRB5_LOGIN_MODULE, REQUIRED, options);

            return entries;
        }

    }

    private static class UsernamePasswordCBH implements CallbackHandler {
        private final String username;
        private final char[] password;

        private UsernamePasswordCBH(final String username, final char[] password) {
            this.username = username;
            this.password = password;
        }

        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (Callback current : callbacks) {
                if (current instanceof NameCallback) {
                    NameCallback ncb = (NameCallback) current;
                    ncb.setName(username);
                } else if (current instanceof PasswordCallback) {
                    PasswordCallback pcb = (PasswordCallback) current;
                    pcb.setPassword(password);
                } else {
                    throw new UnsupportedCallbackException(current);
                }
            }

        }

    }

    protected String getCompleteUserPrincipalName() {
        return kerberosConfig.userPrincipalName()
                + (kerberosConfig.userPrincipalRealm().isPresent() ? "@" + kerberosConfig.userPrincipalRealm().get() : "");
    }
}
