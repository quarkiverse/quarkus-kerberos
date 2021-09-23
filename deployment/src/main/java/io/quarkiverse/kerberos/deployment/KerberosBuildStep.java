package io.quarkiverse.kerberos.deployment;

import com.sun.security.auth.module.Krb5LoginModule;

import io.quarkiverse.kerberos.runtime.KerberosAuthenticationMechanism;
import io.quarkiverse.kerberos.runtime.KerberosIdentityProvider;
import io.quarkiverse.kerberos.runtime.KerberosRecorder;
import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.nativeimage.NativeImageResourceBundleBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.deployment.pkg.PackageConfig;

public class KerberosBuildStep {

    @BuildStep
    public FeatureBuildItem featureBuildItem() {
        return new FeatureBuildItem("kerberos");
    }

    @BuildStep
    public AdditionalBeanBuildItem additionalBeans() {
        AdditionalBeanBuildItem.Builder builder = AdditionalBeanBuildItem.builder().setUnremovable()
                .addBeanClass(KerberosAuthenticationMechanism.class)
                .addBeanClass(KerberosIdentityProvider.class);
        return builder.build();
    }

    @BuildStep
    public ReflectiveClassBuildItem reflection() {
        return ReflectiveClassBuildItem
                .builder(Krb5LoginModule.class.getName(), "sun.security.jgss.krb5.Krb5MechFactory",
                        "sun.security.jgss.SunProvider", "sun.security.jgss.spnego.SpNegoMechFactory",
                        "javax.security.auth.kerberos.KerberosPrincipal", "javax.security.auth.kerberos.KerberosKey",
                        "javax.security.auth.kerberos.KeyTab", "javax.security.auth.kerberos.KerberosTicket")
                .build();
    }

    @BuildStep
    ReflectiveClassBuildItem gssManager() {
        return ReflectiveClassBuildItem.builder("sun.security.jgss.GSSContextImpl").fields(true).build();
    }

    @BuildStep
    public NativeImageResourceBundleBuildItem resourceBundleBuildItem() {
        return new NativeImageResourceBundleBuildItem("sun.security.util.AuthResources");
    }

    @BuildStep
    @Record(ExecutionTime.RUNTIME_INIT)
    public void register2(KerberosRecorder rec, PackageConfig packageConfig) throws Exception {
        if (packageConfig.type.equals(PackageConfig.NATIVE)) {
            rec.registerProviderForNative();
        }
    }
}
