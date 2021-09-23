package io.quarkiverse.kerberos.runtime;

import java.util.Optional;

import io.quarkus.runtime.annotations.ConfigItem;
import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;

@ConfigRoot(name = "kerberos", phase = ConfigPhase.RUN_TIME)
public class KerberosConfig {

    /**
     * JAAS Login context name.
     *
     * If this property is set to "KDC" (default) then the JAAS configuration will be created automatically
     * otherwise a JAAS configuration file must be available and contain an entry matching its value.
     * Use 'java.security.auth.login.config' system property to point to this JAAS configuration file.
     * 
     * Note this property will be ignored if a custom {@link io.quarkiverse.kerberos.ServicePrincipalSubjectFactory} is
     * registered, and it creates a non-null service Subject for the current authentication request.
     */
    @ConfigItem(defaultValue = "KDC")
    public String loginContextName;

    /**
     * Specifies if a JAAS configuration 'debug' property should be enabled.
     * Note this property is only effective when {@code loginContextName} is set to 'KDC'
     * and the JAAS configuration is created automatically.
     */
    @ConfigItem(defaultValue = "false")
    public boolean debug;

    /**
     * Points to a service principal keytab file and will be used to set a JAAS configuration 'keyTab' property.
     * Note this property is only effective when {@code loginContextName} is set to 'KDC'
     * and the JAAS configuration is created automatically.
     */
    @ConfigItem
    public Optional<String> keytabPath;

    /**
     * Specifies whether to use Spnego or Kerberos OID.
     */
    @ConfigItem(defaultValue = "true")
    public boolean useSpnegoOid;

    /**
     * Kerberos Service Principal Name.
     * If this property is not set then the service principal name will be calculated by
     * concatenating "HTTP/" and the HTTP Host header value, for example: "HTTP/localhost".
     */
    @ConfigItem
    public Optional<String> servicePrincipalName;

    /**
     * Kerberos Service Principal Name.
     * If this property is set then it will be added to the service principal name, for example,
     * "HTTP/localhost@SERVICE-REALM.COM". Setting the realm property is not required if it matches
     * a default realm set in the Kerberos Distribution Center (KDC) configuration.
     */
    @ConfigItem
    public Optional<String> servicePrincipalRealm;
}
