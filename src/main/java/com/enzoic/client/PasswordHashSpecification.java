package com.enzoic.client;

/**
 * Specifications for a specific password hash - used internally by the Accounts API call
 */
class PasswordHashSpecification {

    /**
     * The hash algorithm for this password specification
     * @return
     */
    public PasswordType getHashType() {
        return hashType;
    }

    /**
     * The salt value to use for this password, if any
     * @return
     */
    public String getSalt() {
        return salt;
    }

    private PasswordType hashType = PasswordType.None;
    private String salt = "";

    PasswordHashSpecification() {

    }

    PasswordHashSpecification(final PasswordType hashType, final String salt) {
        this.hashType = hashType;
        this.salt = salt;
    }
}
