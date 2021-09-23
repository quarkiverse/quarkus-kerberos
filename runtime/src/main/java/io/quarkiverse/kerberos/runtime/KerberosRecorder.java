package io.quarkiverse.kerberos.runtime;

import java.security.Provider;
import java.security.Security;

import io.quarkus.runtime.annotations.Recorder;

@Recorder
public class KerberosRecorder {

    public void registerProviderForNative() throws Exception {
        Provider provider = (Provider) Class.forName("sun.security.jgss.SunProvider").getConstructor().newInstance();
        if (Security.getProvider(provider.getName()) == null) {
            Security.addProvider(provider);
        }
    }
}
