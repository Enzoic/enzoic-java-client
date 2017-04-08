package com.passwordping.client;

/**
 * The response from the CheckPasswords call
 */
class CheckPasswordResponse {

    /**
     * Whether the password is in PasswordsPing's database of known, compromised passwords.  When true, the isRevealedInExposure getter will
     * indicate whether the password was exposed in a data exposure or was found in a common password cracking dictionary.
     * @return
     */
    public boolean isCompromised() {
        return compromised;
    }

    /**
     * Whether the password was exposed in a known data Exposure. If this value is false, the password was found in common password cracking dictionaries, but has not been directly exposed as a user password in a data breach or other Exposure.
     * @return
     */
    public boolean isRevealedInExposure() {
        return revealedInExposure;
    }

    private boolean compromised = false;
    private boolean revealedInExposure = false;
}
