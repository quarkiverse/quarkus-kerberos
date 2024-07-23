package io.quarkiverse.kerberos.client;

import java.util.Optional;

import javax.security.auth.callback.CallbackHandler;

import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

@ConfigMapping(prefix = "kerberos-client")
@ConfigRoot(phase = ConfigPhase.RUN_TIME)
public interface KerberosClientConfig {

    /**
     * JAAS Login context name.
     *
     * If this property is not set then the JAAS configuration will be created automatically
     * otherwise a JAAS configuration file must be available and contain an entry matching its value.
     * Use 'java.security.auth.login.config' system property to point to this JAAS configuration file.
     *
     * Note this property will be ignored if a custom {@link io.quarkiverse.kerberos.client.UserPrincipalSubjectFactory} is
     * registered and creates a non-null client Subject.
     */
    Optional<String> loginContextName();

    /**
     * Specifies if a JAAS configuration 'debug' property should be enabled.
     * Note this property is only effective when {@code loginContextName} is not set.
     * and the JAAS configuration is created automatically.
     */
    @WithDefault("false")
    boolean debug();

    /**
     * Points to a user principal keytab file and will be used to set a JAAS configuration 'keyTab' property.
     * Note this property is only effective when {@code loginContextName} is not set.
     * and the JAAS configuration is created automatically.
     */
    Optional<String> keytabPath();

    /**
     * User Principal name.
     */
    String userPrincipalName();

    /**
     * Kerberos User Principal Realm Name.
     * If this property is set then it will be added to the user principal name, for example,
     * "HTTP/localhost@SERVICE-REALM.COM". Setting the realm property is not required if it matches
     * a default realm set in the Kerberos Key Distribution Center (KDC) configuration.
     */
    Optional<String> userPrincipalRealm();

    /**
     * Service Principal name
     */
    @WithDefault("HTTP/localhost")
    String servicePrincipalName();

    /**
     * User principal password.
     * Set this property only if using {@code keytabPath}, custom {@linkplain CallbackHandler} or
     * {@linkplain UserPrincipalSubjectFactory} is not possible.
     */
    Optional<String> userPrincipalPassword();

    /**
     * Specifies whether to use Spnego or Kerberos OID.
     */
    @WithDefault("true")
    boolean useSpnegoOid();
}
