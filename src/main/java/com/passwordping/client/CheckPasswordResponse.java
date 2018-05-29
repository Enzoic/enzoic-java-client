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
    private String md5 = "";
    private String sha1 = "";
    private String sha256 = "";
}
