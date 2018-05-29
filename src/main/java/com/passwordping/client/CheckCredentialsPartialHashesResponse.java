package com.passwordping.client;

/**
 * The response from the CheckPasswords call using partial hashes
 */
class CheckCredentialsPartialHashesResponse {

    /**
     * The list of candidate credentials hashes returned from the CheckCredentials call when
     * partial hashes are being used
     * @return an array of credentials hash strings
     */
    public String[] candidateHashes() {
        return candidateHashes;
    }

    private String[] candidateHashes = new String[0];
}
