package io.quarkiverse.kerberos.deployment;

import io.quarkiverse.kerberos.deployment.devservices.DevServicesConfig;
import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/**
 * Build time configuration for Kerberos.
 */
@ConfigMapping(prefix = "quarkus.kerberos")
@ConfigRoot(phase = ConfigPhase.BUILD_TIME)
public interface KerberosBuildTimeConfig {
    /**
     * If the Kerberos extension is enabled.
     */
    @WithDefault("true")
    boolean enabled();

    /**
     * Dev services configuration.
     */
    public DevServicesConfig devservices();
}
