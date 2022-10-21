package com.enzoic.client;

import java.util.Date;

/**
 * Response object for Accounts API call - internal use only
 */
class AccountsResponse {

    /**
     * The salt value to use for credentials hashes for this account
     * @return String
     */
    public String getSalt() {
        return salt;
    }

    /**
     * The list of password hashes required to be calculated when checking credentials for this account
     * @return PasswordHashSpecification[]
     */
    public PasswordHashSpecification[] getPasswordHashesRequired() {
        return passwordHashesRequired;
    }

    public Date getLastBreachDate() { return lastBreachDate; }

    private String salt = "";
    private PasswordHashSpecification[] passwordHashesRequired = new PasswordHashSpecification[0];
    private Date lastBreachDate;
}
