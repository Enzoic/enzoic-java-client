package com.passwordping.client;

/**
 * The response from the CheckPasswords call using partial hashes
 */
class CheckPasswordPartialHashesResponse {

    /**
     * The list of candidate password hashes returned from the CheckPasswords call when
     * partial hashes are being used
     * @return an array of CheckPasswordResponses
     */
    public CheckPasswordResponse[] candidates() {
        return candidates;
    }

    private CheckPasswordResponse[] candidates = new CheckPasswordResponse[0];
}
