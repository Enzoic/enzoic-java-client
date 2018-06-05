package com.passwordping.client;

/**
 * The response from the CheckPasswordsEx call
 */
class CheckPasswordExResponse {

    /**
     * This is a gauge of how frequently the password has been seen in data breaches. The value is simply the percent
     * of data breaches indexed by PasswordPing that have contained at least one instance of this password, i.e. if
     * the value is 13, that means 13% of the exposures that PasswordPing has indexed contained this password at least
     * one time. This value can be used to gauge how dangerous this password is by how common it is.
     * @return
     */
    public int relativeExposureFrequency() { return relativeExposureFrequency; }

    /**
     * Whether the password was exposed in a known data Exposure. If this value is false, the password was found in common password cracking dictionaries, but has not been directly exposed as a user password in a data breach or other Exposure.
     * @return
     */
    public boolean isRevealedInExposure() {
        return revealedInExposure;
    }

    private int relativeExposureFrequency = 0;
    private boolean revealedInExposure = false;

    public CheckPasswordExResponse(boolean revealedInExposure, int relativeExposureFrequency) {
        this.relativeExposureFrequency = relativeExposureFrequency;
        this.revealedInExposure = revealedInExposure;
    }
}
