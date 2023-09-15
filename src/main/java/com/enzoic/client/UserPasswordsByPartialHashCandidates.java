package com.enzoic.client;

import java.util.Date;

/**
 * Information about all of the passwords Enzoic has for a given user
 */
public class UserPasswordsByPartialHashCandidates {
    public UserPasswordsByPartialHash[] getCandidates() { return candidates; }
    private UserPasswordsByPartialHash[] candidates;
}
