package io.quarkiverse.kerberos.deployment.devservices;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.logging.Logger;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.Base58;
import org.testcontainers.utility.DockerImageName;

import io.quarkiverse.kerberos.deployment.KerberosBuildStep.IsEnabled;
import io.quarkiverse.kerberos.deployment.KerberosBuildTimeConfig;
import io.quarkus.bootstrap.classloading.QuarkusClassLoader;
import io.quarkus.deployment.IsDockerWorking;
import io.quarkus.deployment.IsNormal;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.DevServicesConfigResultBuildItem;
import io.quarkus.deployment.builditem.DevServicesSharedNetworkBuildItem;
import io.quarkus.deployment.builditem.LaunchModeBuildItem;
import io.quarkus.deployment.dev.devservices.GlobalDevServicesConfig;
import io.quarkus.deployment.logging.LoggingSetupBuildItem;
import io.quarkus.devservices.common.ContainerAddress;
import io.quarkus.devservices.common.ContainerLocator;
import io.quarkus.runtime.LaunchMode;

public class KerberosDevServicesProcessor {
    private static final Logger LOG = Logger.getLogger(KerberosDevServicesProcessor.class);

    private static final String JAVA_OPTS = "JAVA_OPTS";
    private static final int KERBEROS_KDC_PORT = 88;
    private static final int KERBEROS_KDC_PORT_2 = 464;
    private static final int KERBEROS_ADMIN_SERVER_PORT = 749;
    private static final String CONFIG_PREFIX = "quarkus.kerberos.";
    private static final String KERBEROS_LOGIN_CONTEXT_NAME_PROP = CONFIG_PREFIX + "login-context-name";
    private static final String KERBEROS_SERVICE_PRINC_NAME_PROP = CONFIG_PREFIX + "service-principal-name";
    private static final String DEFAULT_KERBEROS_SERVICE_PRINC_NAME = "HTTP/localhost";
    private static final String KERBEROS_SERVICE_PRINC_REALM_PROP = CONFIG_PREFIX + "service-principal-realm";
    private static final String DEFAULT_KERBEROS_SERVICE_PRINC_REALM = "EXAMPLE.COM";
    private static final String KERBEROS_SERVICE_PRINC_PWD_PROP = CONFIG_PREFIX + "service-principal-password";
    private static final String DEFAULT_KERBEROS_SERVICE_PRINC_PWD = "servicepwd";

    /**
     * Label to add to shared Dev Service for Kerberos running in containers.
     * This allows other applications to discover the running service and use it instead of starting a new instance.
     */
    private static final String DEV_SERVICE_LABEL = "quarkus-dev-service-kerberos";
    private static final ContainerLocator kerberosDevModeContainerLocator = new ContainerLocator(DEV_SERVICE_LABEL,
            KERBEROS_KDC_PORT);
    private static final ContainerLocator kerberosDevModeAdminServerContainerLocator = new ContainerLocator(DEV_SERVICE_LABEL,
            KERBEROS_ADMIN_SERVER_PORT);

    private static volatile List<Closeable> closeables;
    private static volatile boolean first = true;
    private final IsDockerWorking isDockerWorking = new IsDockerWorking(true);
    private static volatile DevServicesConfig capturedDevServicesConfiguration;
    private static volatile KerberosDevServicesConfigBuildItem existingDevServiceConfig;

    @BuildStep(onlyIfNot = IsNormal.class, onlyIf = { IsEnabled.class, GlobalDevServicesConfig.Enabled.class })
    public KerberosDevServicesConfigBuildItem startKerberosContainer(
            Optional<DevServicesSharedNetworkBuildItem> devServicesSharedNetworkBuildItem,
            BuildProducer<DevServicesConfigResultBuildItem> devServices,
            KerberosBuildTimeConfig config,
            LaunchModeBuildItem launchMode,
            LoggingSetupBuildItem loggingSetupBuildItem) {

        DevServicesConfig currentDevServicesConfiguration = config.devservices;
        // Figure out if we need to shut down and restart any existing Kerberos container
        // if not and the Kerberos container has already started we just return
        boolean restartRequired = false;
        if (closeables != null) {
            restartRequired = !currentDevServicesConfiguration.equals(capturedDevServicesConfiguration);
            if (!restartRequired) {
                return existingDevServiceConfig;
            }
            for (Closeable closeable : closeables) {
                try {
                    closeable.close();
                } catch (Throwable e) {
                    LOG.error("Failed to stop Kerberos container", e);
                }
            }
            closeables = null;
            capturedDevServicesConfiguration = null;
            existingDevServiceConfig = null;
        }
        capturedDevServicesConfiguration = currentDevServicesConfiguration;
        StartResult startResult;
        try {
            startResult = startContainer(devServicesSharedNetworkBuildItem.isPresent(), restartRequired);
            if (startResult == null) {
                return null;
            }

            closeables = startResult.closeable != null ? Collections.singletonList(startResult.closeable) : null;

            if (first) {
                first = false;
                Runnable closeTask = new Runnable() {
                    @Override
                    public void run() {
                        if (closeables != null) {
                            for (Closeable closeable : closeables) {
                                try {
                                    closeable.close();
                                } catch (Throwable t) {
                                    LOG.error("Failed to stop Kerberos container", t);
                                }
                            }
                        }
                        first = true;
                        closeables = null;
                        capturedDevServicesConfiguration = null;
                    }
                };
                QuarkusClassLoader cl = (QuarkusClassLoader) Thread.currentThread().getContextClassLoader();
                ((QuarkusClassLoader) cl.parent()).addCloseTask(closeTask);
            }

        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
        LOG.info("Dev Services for Kerberos started.");

        return prepareConfiguration(devServices, startResult.krb5CfgPath, startResult.shared);
    }

    private KerberosDevServicesConfigBuildItem prepareConfiguration(BuildProducer<DevServicesConfigResultBuildItem> devServices,
            String krb5CfgPath,
            boolean shared) {

        System.setProperty("java.security.krb5.conf", krb5CfgPath);

        devServices
                .produce(new DevServicesConfigResultBuildItem(KERBEROS_SERVICE_PRINC_PWD_PROP, getServicePrincipalPassword()));

        existingDevServiceConfig = new KerberosDevServicesConfigBuildItem(Collections.emptyMap());
        return existingDevServiceConfig;
    }

    private StartResult startContainer(boolean useSharedContainer, boolean restart) {
        if (!capturedDevServicesConfiguration.enabled) {
            // explicitly disabled
            LOG.debug("Not starting Dev Services for Kerberos as it has been disabled in the config");
            return null;
        }
        if (System.getProperty("java.security.krb5.conf") != null && !restart) {
            LOG.debug("Not starting Dev Services for Kerberos as the java.security.krb5.conf system property is already set");
            return null;
        }
        if (System.getenv("KRB5_CONFIG") != null) {
            LOG.debug("Not starting Dev Services for Kerberos as the KRB5_CONFIG environment variable already exists");
            return null;
        }
        if (isLoginContextNameConfigured()) {
            LOG.debug("Not starting Dev Services for Kerberos as the JAAS login context name is already configured");
            return null;
        }

        if (!isDockerWorking.getAsBoolean()) {
            LOG.warn("Please get a working docker instance");
            return null;
        }

        final Optional<ContainerAddress> maybeContainerAddress = kerberosDevModeContainerLocator.locateContainer(
                capturedDevServicesConfiguration.serviceName,
                capturedDevServicesConfiguration.shared,
                LaunchMode.current());

        final Supplier<StartResult> defaultKerberosContainerSupplier = () -> {
            String imageName = capturedDevServicesConfiguration.imageName;
            DockerImageName dockerImageName = DockerImageName.parse(imageName)
                    .asCompatibleSubstituteFor(imageName);
            QuarkusKerberosContainer kerberosContainer = new QuarkusKerberosContainer(dockerImageName,
                    useSharedContainer,
                    capturedDevServicesConfiguration.serviceName,
                    capturedDevServicesConfiguration.shared,
                    capturedDevServicesConfiguration.javaOpts);

            kerberosContainer.start();
            LOG.info(kerberosContainer.getLogs());
            kerberosContainer.createTestPrincipals(getUserPrincipals());
            String krb5CfgPath = kerberosContainer.createKrb5File();

            return new StartResult(new Closeable() {
                @Override
                public void close() {
                    kerberosContainer.close();

                    LOG.info("Dev Services for Kerberos shut down.");
                }
            },
                    krb5CfgPath,
                    false);
        };

        return maybeContainerAddress
                .map(containerAddress -> new StartResult(null, getSharedKrb5CfgPath(containerAddress), true))
                .orElseGet(defaultKerberosContainerSupplier);
    }

    private Map<String, String> getUserPrincipals() {
        if (capturedDevServicesConfiguration.principals.isEmpty()) {
            Map<String, String> users = new LinkedHashMap<String, String>();
            users.put("alice", "alice");
            users.put("bob", "bob");
            return users;
        } else {
            return capturedDevServicesConfiguration.principals;
        }
    }

    private static String getSharedKrb5CfgPath(ContainerAddress sharedKerberos) {
        Optional<ContainerAddress> sharedKerberosAdmin = kerberosDevModeAdminServerContainerLocator.locateContainer(
                capturedDevServicesConfiguration.serviceName,
                capturedDevServicesConfiguration.shared,
                LaunchMode.current());
        return createKrb5Config("0.0.0.0".equals(sharedKerberos.getHost()) ? "localhost" : sharedKerberos.getHost(),
                String.valueOf(sharedKerberos.getPort()),
                String.valueOf(sharedKerberosAdmin.get().getPort()));
    }

    private static String createKrb5Config(String host, String kdcPort, String kdcAdminPort) {
        try (BufferedReader reader = new BufferedReader(
                new StringReader(
                        new String(Thread.currentThread().getContextClassLoader()
                                .getResourceAsStream("/krb5ClientTemplate.conf")
                                .readAllBytes())))) {
            String content = reader.lines().collect(Collectors.joining(System.lineSeparator()));
            content = content.replaceAll("<host>", host);
            content = content.replaceAll("<kdc_port>", kdcPort);
            content = content.replaceAll("<admin_server_port>", kdcAdminPort);
            content = content.replaceAll("<realm>", getRealm());
            Path tmp = Files.createTempFile("devservices-krb5", ".conf");
            Files.write(tmp, content.getBytes());
            String krb5ConfigPath = tmp.toAbsolutePath().toString();
            LOG.infof("Kerberos configuration file path: %s, mapped KDC port: %s, mapped admin server port: %s", krb5ConfigPath,
                    kdcPort, kdcAdminPort);
            return krb5ConfigPath;
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    private static class StartResult {
        private final Closeable closeable;
        private final String krb5CfgPath;
        private final boolean shared;

        public StartResult(Closeable closeable, String krb5CfgPath, boolean shared) {
            this.closeable = closeable;
            this.krb5CfgPath = krb5CfgPath;
            this.shared = shared;
        }
    }

    private static class QuarkusKerberosContainer extends GenericContainer {
        private final boolean useSharedNetwork;
        private final String containerLabelValue;
        private final Optional<String> javaOpts;
        private final boolean sharedContainer;
        private String hostName = null;

        public QuarkusKerberosContainer(DockerImageName dockerImageName, boolean useSharedNetwork,
                String containerLabelValue,
                boolean sharedContainer, Optional<String> javaOpts) {
            super(dockerImageName);
            this.useSharedNetwork = useSharedNetwork;
            this.containerLabelValue = containerLabelValue;
            this.sharedContainer = sharedContainer;
            this.javaOpts = javaOpts;
        }

        @Override
        protected void configure() {
            super.configure();
            if (sharedContainer && LaunchMode.current() == LaunchMode.DEVELOPMENT) {
                withLabel(DEV_SERVICE_LABEL, containerLabelValue);
            }

            if (useSharedNetwork) {
                setNetwork(Network.SHARED);
                hostName = "kerberos-" + Base58.randomString(5);
                setNetworkAliases(Collections.singletonList(hostName));
            } else {
                withExposedPorts(KERBEROS_KDC_PORT, KERBEROS_KDC_PORT_2, KERBEROS_ADMIN_SERVER_PORT);
            }

            withStartupTimeout(Duration.ofMillis(20000));
            withEnv("KRB5_REALM", getRealm());
            withEnv("KRB5_KDC", "localhost");
            withEnv("KRB5_PASS", "mypass");
            waitingFor(Wait.forLogMessage("Principal \"admin/admin@" + getRealm() + "\" created.*", 1));

            if (javaOpts.isPresent()) {
                addEnv(JAVA_OPTS, javaOpts.get());
            }
        }

        public void createTestPrincipals(Map<String, String> userPrincipals) {
            try {
                // Service principal
                execInContainer("kadmin.local", "-q",
                        "addprinc -pw " + getServicePrincipalPassword() + " " + getServicePrincipalName());
                // User principals
                for (Map.Entry<String, String> entry : userPrincipals.entrySet()) {
                    execInContainer("kadmin.local", "-q", "addprinc -pw " + entry.getValue() + " " + entry.getKey());
                }
            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }

        public String createKrb5File() {
            return createKrb5Config(getHost(), getMappedPort(KERBEROS_KDC_PORT).toString(),
                    getMappedPort(KERBEROS_ADMIN_SERVER_PORT).toString());
        }

        @Override
        public String getHost() {
            if (useSharedNetwork) {
                return hostName;
            }
            return super.getHost();
        }
    }

    private static String getRealm() {
        if (capturedDevServicesConfiguration.realm.isPresent()) {
            return capturedDevServicesConfiguration.realm.get();
        }
        return ConfigProvider.getConfig().getOptionalValue(KERBEROS_SERVICE_PRINC_REALM_PROP, String.class)
                .orElse(DEFAULT_KERBEROS_SERVICE_PRINC_REALM);
    }

    private static String getServicePrincipalPassword() {
        return ConfigProvider.getConfig().getOptionalValue(KERBEROS_SERVICE_PRINC_PWD_PROP, String.class)
                .orElse(DEFAULT_KERBEROS_SERVICE_PRINC_PWD);
    }

    private static String getServicePrincipalName() {
        return ConfigProvider.getConfig().getOptionalValue(KERBEROS_SERVICE_PRINC_NAME_PROP, String.class)
                .orElse(DEFAULT_KERBEROS_SERVICE_PRINC_NAME);
    }

    private static boolean isLoginContextNameConfigured() {
        return ConfigProvider.getConfig().getOptionalValue(KERBEROS_LOGIN_CONTEXT_NAME_PROP, String.class).isPresent();
    }
}
