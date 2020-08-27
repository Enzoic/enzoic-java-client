package com.enzoic.client;

/**
 * The response from the CheckPasswords call
 */
class CheckPasswordResponse {

    /**
     * Whether the password is in PasswordsPing's database of known, compromised passwords.  When true, the isRevealedInExposure getter will
     * indicate whether the password was exposed in a data exposure or was found in a common password cracking dictionary.
     * @return boolean indicating compromised status
     */
    public boolean isCompromised() {
        return compromised;
    }

    /**
     * Whether the password was exposed in a known data Exposure. If this value is false, the password was found in common password cracking dictionaries, but has not been directly exposed as a user password in a data breach or other Exposure.
     * @return boolean indicating whether password has been revealed in an exposure
     */
    public boolean isRevealedInExposure() {
        return revealedInExposure;
    }

    /**
     * This is a gauge of how frequently the password has been seen in data breaches. The value is simply the percent
     * of data breaches indexed by Enzoic that have contained at least one instance of this password, i.e. if
     * the value is 13, that means 13% of the exposures that Enzoic has indexed contained this password at least
     * one time. This value can be used to gauge how dangerous this password is by how common it is.
     * @return relative exposure frequency score
     */
    public int relativeExposureFrequency() { return relativeExposureFrequency; }

    /**
     * The total number of exposures this password has appeared in. While it’s a bad idea to ever use a password that
     * has been publicly exposed even a single time, this number can be used to determine how common a password is and
     * how often it has been exposed.
     * @return a count of the number of exposures this password was seen in
     */
    public int exposureCount() { return exposureCount; }

    /**
     * MD5 hash of the returned candidate.  Can be compared to the local MD5 to determine if this candidate is a match.
     * @return a string containing the MD5 of this candidate password hash
     */
    public String md5() { return md5; }

    /**
     * SHA1 hash of the returned candidate.  Can be compared to the local SHA1 to determine if this candidate is a match.
     * @return a string containing the SHA1 of this candidate password hash
     */
    public String sha1() { return sha1; }

    /**
     * SHA256 hash of the returned candidate.  Can be compared to the local SHA256 to determine if this candidate is a match.
     * @return a string containing the SHA256 of this candidate password hash
     */
    public String sha256() { return sha256; }

    private boolean compromised = false;
    private boolean revealedInExposure = false;
    private int relativeExposureFrequency = 0;
    private int exposureCount = 0;
    private String md5 = "";
    private String sha1 = "";
    private String sha256 = "";
}
