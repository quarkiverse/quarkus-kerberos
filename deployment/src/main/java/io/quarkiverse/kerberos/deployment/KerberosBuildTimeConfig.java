package io.quarkiverse.kerberos.deployment;

import io.quarkiverse.kerberos.deployment.devservices.DevServicesConfig;
import io.quarkus.runtime.annotations.ConfigItem;
import io.quarkus.runtime.annotations.ConfigRoot;

/**
 * Build time configuration for Kerberos.
 */
@ConfigRoot
public class KerberosBuildTimeConfig {
    /**
     * If the Kerberos extension is enabled.
     */
    @ConfigItem(defaultValue = "true")
    public boolean enabled;

    /**
     * Dev services configuration.
     */
    @ConfigItem
    public DevServicesConfig devservices;
}
