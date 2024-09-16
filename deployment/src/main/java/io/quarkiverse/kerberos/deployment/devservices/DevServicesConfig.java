package io.quarkiverse.kerberos.deployment.devservices;

import java.util.Map;
import java.util.Optional;

import io.quarkus.runtime.annotations.ConfigGroup;
import io.smallrye.config.WithDefault;

@ConfigGroup
public interface DevServicesConfig {

    /**
     * If DevServices has been explicitly enabled or disabled.
     * <p>
     * When DevServices is enabled Quarkus will attempt to automatically configure and start
     * Kerberos when running in Dev or Test mode and when Docker is running.
     */
    @WithDefault("true")
    boolean enabled();

    /**
     * The container image name to use, for container based DevServices providers.
     * See https://github.com/kerberos-io/kerberos-docker.
     */
    @WithDefault("gcavalcante8808/krb5-server")
    String imageName();

    /**
     * Indicates if the Kerberos container managed by Quarkus Dev Services is shared.
     * When shared, Quarkus looks for running containers using label-based service discovery.
     * If a matching container is Kerberos, it is used, and so a second one is not started.
     * Otherwise, Dev Services for Kerberos starts a new container.
     * <p>
     * The discovery uses the {@code quarkus-dev-service-label} label.
     * The value is configured using the {@code service-name} property.
     * <p>
     * Container sharing is only used in dev mode.
     */
    @WithDefault("true")
    boolean shared();

    /**
     * The value of the {@code quarkus-dev-service-kerberos} label attached to the started container.
     * This property is used when {@code shared} is set to {@code true}.
     * In this case, before starting a container, Dev Services for Kerberos looks for a container with the
     * {@code quarkus-dev-service-kerberos} label
     * set to the configured value. If found, it will use this container instead of starting a new one. Otherwise it
     * starts a new container with the {@code quarkus-dev-service-kerberos} label set to the specified value.
     * <p>
     * Container sharing is only used in dev mode.
     */
    @WithDefault("quarkus-kerberos")
    String serviceName();

    /**
     * The JAVA_OPTS passed to the keycloak JVM
     */
    Optional<String> javaOpts();

    /**
     * The Kerberos user principals map containing the principal name and password pairs.
     * If this map is empty then two principals, 'alice' and 'bob' with the passwords matching their names will be created.
     */
    public Map<String, String> principals();

    /**
     * The Kerberos realm.
     */
    public Optional<String> realm();
}
