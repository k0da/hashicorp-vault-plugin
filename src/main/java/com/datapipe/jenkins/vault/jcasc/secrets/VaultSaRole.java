package com.datapipe.jenkins.vault.jcasc.secrets;

import java.util.Objects;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.ProtectedExternally;

@Restricted(ProtectedExternally.class)
public class VaultSaRole {

    private String saRole;

    public VaultSaRole(String saRole) {
        this.saRole = saRole;
    }

    public String getSaRole() {
        return saRole;
    }

    @Override
    public int hashCode() {
        return Objects.hash(saRole);
    }
}
