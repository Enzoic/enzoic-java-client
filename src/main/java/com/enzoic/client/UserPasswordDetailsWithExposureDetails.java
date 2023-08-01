package com.enzoic.client;

/**
 * The details for a specific user password.
 */
public class UserPasswordDetailsWithExposureDetails {

    /**
     * The hash type the Password field contains.  Whenever possible, this will be PasswordType.Plaintext, but in the event Enzoic does not have a cracked plaintext equivalent for the password which was found, this will instead be the raw hash type that was found.  In this case, the Password field will contain a hash rather than a plaintext value and the Salt field may contain the salt value for the hash, if this is a hash type that employs a salt.
     * @return PasswordType
     */
    public PasswordType getHashType() { return hashType; }

    /**
     * The password for this user.  Whenever possible, this will be PasswordType.Plaintext, but in the event Enzoic does not have a cracked plaintext equivalent for the password which was found, this will instead be the raw hash that was found.  This is provided so that you can hash a plaintext password into the same format and compare to see if they are equal.
     * @return String
     */
    public String getPassword() { return password; }

    /**
     * The salt for the provided password hash, when appropriate.  Whenever possible, this will be PasswordType.Plaintext, but in the event Enzoic does not have a cracked plaintext equivalent for the password which was found, the raw hash that was found will be returned.  For hash types where a salt is employed, this is the salt value which should be used.
     * @return String
     */
    public String getSalt() { return salt; }

    /**
     * An array of ExposureDetails.
     * @return String[]
     */
    public ExposureDetails[] getExposures() { return exposures; }

    private PasswordType hashType;
    private String password;
    private String salt;
    private ExposureDetails[] exposures;
}
