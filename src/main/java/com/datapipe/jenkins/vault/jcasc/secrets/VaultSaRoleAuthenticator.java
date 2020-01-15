package com.datapipe.jenkins.vault.jcasc.secrets;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import java.util.Objects;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class VaultSaRoleAuthenticator extends VaultAuthenticatorWithExpiration {

    private final static Logger LOGGER = Logger.getLogger(VaultSaRoleAuthenticator.class.getName());
    private static final String SERVICE_ACCOUNT_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    private VaultSaRole saRole;

    public VaultSaRoleAuthenticator(VaultSaRole appRole, String mountPath) {
        this.saRole = saRole;
        this.mountPath = mountPath;
    }

    @SuppressFBWarnings(value = "DMI_HARDCODED_ABSOLUTE_FILENAME")
    public void authenticate(Vault vault, VaultConfig config) throws VaultException {
        String jwt;
        try {
            jwt = Files.lines(Paths.get(SERVICE_ACCOUNT_TOKEN_PATH)).collect(Collectors.joining());
        } catch (IOException e) {
            throw new VaultPluginException("could not get JWT from Service Account Token", e);
        }
	
        if (isTokenTTLExpired()) {
            // authenticate
            currentAuthToken = vault.auth()
                .loginByJwt(mountPath, saRole.getSaRole(), jwt)
                .getAuthClientToken();
            config.token(currentAuthToken).build();
            LOGGER.log(Level.FINE, "Login to Vault using kubernetes service account successful");
            getTTLExpiryOfCurrentToken(vault);
        } else {
            // make sure current auth token is set in config
            config.token(currentAuthToken).build();
        }
    }

    @Override
    public boolean equals(Object o) {
        return super.equals(o);
    }

    @Override
    public int hashCode() {
        return Objects.hash(appRole, jwt);
    }
}
