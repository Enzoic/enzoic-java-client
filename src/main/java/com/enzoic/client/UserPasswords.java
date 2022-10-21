package com.enzoic.client;

import java.util.Date;

/**
 * Information about all of the passwords Enzoic has for a given user
 */
public class UserPasswords {

    /**
     * The last time a new exposure/breach was found containing this user
     * @return Date
     */
    public Date getLastBreachDate() { return lastBreachDate; }

    /**
     * An array of UserPasswordDetails objects containing the plaintext or hashed passwords Enzoic has for this user
     * @return UserPasswordsDetails[]
     */
    public UserPasswordDetails[] getPasswords() { return passwords; }

    private Date lastBreachDate;
    private UserPasswordDetails[] passwords;
}
