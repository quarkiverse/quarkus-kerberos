package io.quarkiverse.kerberos.test;

import static javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.enterprise.context.ApplicationScoped;
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

import io.quarkiverse.kerberos.ServicePrincipalSubjectFactory;

@ApplicationScoped
public class TestSubjectFactory implements ServicePrincipalSubjectFactory {

    private static final boolean IS_IBM = System.getProperty("java.vendor").contains("IBM");

    @Override
    public Subject getSubjectForServicePrincipal(String servicePrincipalName) {
        try {
            return login(servicePrincipalName, "servicepwd".toCharArray());
        } catch (LoginException e) {
            throw new RuntimeException(e);
        }
    }

    static Subject login(final String userName, final char[] password) throws LoginException {
        Subject theSubject = new Subject();
        CallbackHandler cbh = new UsernamePasswordCBH(userName, password);
        LoginContext lc = new LoginContext("KDC", theSubject, cbh, createJaasConfiguration());
        lc.login();

        return theSubject;
    }

    static class UsernamePasswordCBH implements CallbackHandler {

        /*
         * Note: We use CallbackHandler implementations like this in test cases as test cases need to run unattended, a true
         * CallbackHandler implementation should interact directly with the current user to prompt for the username and
         * password.
         *
         * i.e. In a client app NEVER prompt for these values in advance and provide them to a CallbackHandler like this.
         */

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

    private static Configuration createJaasConfiguration() {
        return new Configuration() {

            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                if (!"KDC".equals(name)) {
                    throw new IllegalArgumentException("Unexpected name '" + name + "'");
                }

                AppConfigurationEntry[] entries = new AppConfigurationEntry[1];
                Map<String, Object> options = new HashMap<>();
                options.put("debug", "true");
                options.put("refreshKrb5Config", "true");

                if (IS_IBM) {
                    options.put("noAddress", "true");
                    options.put("credsType", "both");
                    entries[0] = new AppConfigurationEntry("com.ibm.security.auth.module.Krb5LoginModule", REQUIRED, options);
                } else {
                    options.put("storeKey", "true");
                    options.put("isInitiator", "true");
                    entries[0] = new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule", REQUIRED, options);
                }

                return entries;
            }

        };
    }
}
