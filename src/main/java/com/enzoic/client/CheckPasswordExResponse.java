package com.enzoic.client;

/**
 * The response from the CheckPasswordsEx call
 */
public class CheckPasswordExResponse {

    /**
     * This is a gauge of how frequently the password has been seen in data breaches. The value is simply the percent
     * of data breaches indexed by Enzoic that have contained at least one instance of this password, i.e. if
     * the value is 13, that means 13% of the exposures that Enzoic has indexed contained this password at least
     * one time. This value can be used to gauge how dangerous this password is by how common it is.
     * @return relative exposure frequency score
     */
    public int relativeExposureFrequency() { return relativeExposureFrequency; }

    /**
     * Whether the password was exposed in a known data Exposure. If this value is false, the password was found in common password cracking dictionaries, but has not been directly exposed as a user password in a data breach or other Exposure.
     * @return boolean indicating whether password has been revealed in an exposure
     */
    public boolean isRevealedInExposure() {
        return revealedInExposure;
    }

    /**
     * The total number of exposures this password has appeared in.
     * While it’s a bad idea to ever use a password that has been publicly exposed even a single time, this number can
     * be used to determine how common a password is and how often it has been exposed.
     * @return a count of the number of exposures this password was seen in
     */
    public int exposureCount() { return exposureCount; }

    private final int exposureCount;
    private final int relativeExposureFrequency;
    private final boolean revealedInExposure;

    public CheckPasswordExResponse(boolean revealedInExposure, int relativeExposureFrequency, int exposureCount) {
        this.relativeExposureFrequency = relativeExposureFrequency;
        this.revealedInExposure = revealedInExposure;
        this.exposureCount = exposureCount;
    }
}
