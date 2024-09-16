package io.quarkiverse.kerberos.deployment;

import java.util.function.BooleanSupplier;

import io.quarkiverse.kerberos.runtime.KerberosAuthenticationMechanism;
import io.quarkiverse.kerberos.runtime.KerberosIdentityProvider;
import io.quarkiverse.kerberos.runtime.KerberosProducer;
import io.quarkiverse.kerberos.runtime.KerberosRecorder;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.nativeimage.NativeImageResourceBundleBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.deployment.pkg.NativeConfig;

public class KerberosBuildStep {

    @BuildStep(onlyIf = IsEnabled.class)
    public FeatureBuildItem featureBuildItem() {
        return new FeatureBuildItem("kerberos");
    }

    @BuildStep(onlyIf = IsEnabled.class)
    public AdditionalBeanBuildItem additionalBeans() {
        AdditionalBeanBuildItem.Builder builder = AdditionalBeanBuildItem.builder().setUnremovable()
                .addBeanClass(KerberosAuthenticationMechanism.class)
                .addBeanClass(KerberosIdentityProvider.class)
                .addBeanClass(KerberosProducer.class);
        return builder.build();
    }

    @BuildStep(onlyIf = IsEnabled.class)
    public ReflectiveClassBuildItem reflection() {
        return ReflectiveClassBuildItem
                .builder("sun.security.jgss.krb5.Krb5MechFactory",
                        "sun.security.jgss.SunProvider", "sun.security.jgss.spnego.SpNegoMechFactory",
                        "javax.security.auth.kerberos.KerberosPrincipal", "javax.security.auth.kerberos.KerberosKey",
                        "javax.security.auth.kerberos.KeyTab", "javax.security.auth.kerberos.KerberosTicket")
                .build();
    }

    @BuildStep(onlyIf = IsEnabled.class)
    ReflectiveClassBuildItem gssManager() {
        return ReflectiveClassBuildItem.builder("sun.security.jgss.GSSContextImpl").fields(true).build();
    }

    @BuildStep(onlyIf = IsEnabled.class)
    ReflectiveClassBuildItem loginModules() {
        return ReflectiveClassBuildItem
                .builder(
                        "com.sun.jmx.remote.security.FileLoginModule",
                        "com.sun.security.auth.module.JndiLoginModule",
                        "com.sun.security.auth.module.KeyStoreLoginModule",
                        "com.sun.security.auth.module.Krb5LoginModule",
                        "com.sun.security.auth.module.LdapLoginModule",
                        "com.sun.security.auth.module.NTLoginModule",
                        "com.sun.security.auth.module.UnixLoginModule")
                .build();
    }

    @BuildStep(onlyIf = IsEnabled.class)
    public NativeImageResourceBundleBuildItem resourceBundleBuildItem() {
        return new NativeImageResourceBundleBuildItem("sun.security.util.AuthResources");
    }

    @BuildStep(onlyIf = IsEnabled.class)
    @Record(ExecutionTime.RUNTIME_INIT)
    public void register2(KerberosRecorder rec, NativeConfig nativeConfig) throws Exception {
        if (nativeConfig.enabled()) {
            rec.registerProviderForNative();
        }
    }

    public static class IsEnabled implements BooleanSupplier {
        KerberosBuildTimeConfig config;

        public boolean getAsBoolean() {
            return config.enabled();
        }
    }
}
