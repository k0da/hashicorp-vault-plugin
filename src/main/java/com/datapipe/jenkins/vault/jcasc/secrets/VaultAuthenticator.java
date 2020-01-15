package com.datapipe.jenkins.vault.jcasc.secrets;

import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;

public interface VaultAuthenticator {
    void authenticate(Vault vault, VaultConfig config) throws VaultException;
    static VaultAuthenticator of(String token) {
        return new VaultSingleTokenAuthenticator(token);
    }
    static VaultAuthenticator of(VaultAppRole appRole, String mountPath) {
        return new VaultAppRoleAuthenticator(appRole, mountPath);
    }
    static VaultAuthenticator of(VaultSaRole saRole, String mountPath) {
        return new VaultSaRoleAuthenticator(saRole, mountPath);
    }
    static VaultAuthenticator of(VaultUsernamePassword vaultUsernamePassword, String mountPath) {
        return new VaultUserPassAuthenticator(vaultUsernamePassword, mountPath);
    }
}
