package com.enzoic.client;

import java.util.Date;

/**
 * Information about all of the passwords Enzoic has for a given user
 */
public class UserPasswordsByPartialHash extends UserPasswords {

    /**
     * An SHA-256 hash of the user this data is for
     * @return String
     */
    public String getUsernameHash() { return usernameHash; }

    private String usernameHash;
}
