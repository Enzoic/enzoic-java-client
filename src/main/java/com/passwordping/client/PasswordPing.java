package com.passwordping.client;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.ResourceBundle;
import com.google.gson.Gson;
import org.apache.commons.io.IOUtils;
import com.passwordping.client.utilities.Hashing;

/**
 * This is the main entry point for accessing PasswordPing.
 *
 * Create this class with your API Key and Secret and then call the desired methods on the class
 * to access the PasswordPing API.
 */
public class PasswordPing {

    private static final String CREDENTIALS_API_PATH = "/credentials";
    private static final String PASSWORDS_API_PATH = "/passwords";
    private static final String EXPOSURES_API_PATH = "/exposures";
    private static final String ACCOUNTS_API_PATH = "/accounts";
    private static final String ALERTS_SERVICE_PATH = "/alert-subscriptions";

    private String apiKey;
    private String secret;
    private String authString;
    private String apiBaseURL;

    /**
     * Creates a new instance of PasswordPing
     * @param apiKey your PasswordPing API key
     * @param secret your PasswordPing API secret
     */
    public PasswordPing(final String apiKey, final String secret) {
        this(apiKey, secret, null);
    }

    /**
     * Creates a new instance of PasswordPing
     * @param apiKey your PasswordPing API key
     * @param secret your PasswordPing API secret
     * @param apiBaseURL override the default base API URL with an alternate - typically not necessary
     */
    public PasswordPing(final String apiKey, final String secret, final String apiBaseURL) {
        if (apiKey == null || apiKey.length() == 0) {
            throw new IllegalArgumentException("API Key cannot be null or empty");
        }

        if (secret == null || secret.length() == 0) {
            throw new IllegalArgumentException("Secret cannot be null or empty");
        }

        String baseURL = apiBaseURL;
        if (baseURL == null || baseURL.length() == 0) {
            baseURL = GetProperty("defaultAPIBaseURL", "https://api.passwordping.com/v1");
        }

        this.apiKey = apiKey;
        this.secret = secret;
        this.apiBaseURL = baseURL;
        this.authString = CalcAuthString(apiKey, secret);
    }

    /**
     * Calls the PasswordPing CheckCredentials API in a secure fashion to check whether the provided username and password
     * are known to be compromised.
     * This call is made securely to the server - only a salted and hashed representation of the credentials are passed and
     * the salt value is not passed along with it.
     * @see <a href="https://www.passwordping.com/docs/credentials-api">https://www.passwordping.com/docs/credentials-api</a>
     * @param username the username to check
     * @param password the password to check
     * @return if true, then the credentials are known to be compromised
     * @throws IOException Could not communicate with PasswordPing server.
     * @throws RuntimeException Runtime errors indicated by message
     */
    public boolean CheckCredentials(final String username, final String password)
            throws IOException, RuntimeException {

        String response = MakeRestCall(
                apiBaseURL + ACCOUNTS_API_PATH + "?username=" +
                        URLEncoder.encode(Hashing.sha256(username), "UTF-8"),
                "GET", null);

        if (response.equals("404")) {
            // this is all we needed to check for this - email wasn't even in the DB
            return false;
        }

        // deserialize response
        AccountsResponse accountsResponse = new Gson().fromJson(response, AccountsResponse.class);

        // loop through the hashes required
        ArrayList<PasswordHashSpecification> hashesRequired = new ArrayList<PasswordHashSpecification>();
        hashesRequired.addAll(Arrays.asList(accountsResponse.getPasswordHashesRequired()));

        //String queryString = "";
        int bcryptCount = 0;

        StringBuilder queryString = new StringBuilder();
        for (int i = 0 ; i < Math.min(50, hashesRequired.size()); i++) {
            PasswordHashSpecification hashSpec = hashesRequired.get(i);

            // bcrypt gets far too expensive for good response time if there are many of them to calculate.
            // some mostly garbage accounts have accumulated a number of them in our DB and if we happen to hit one it
            // kills performance, so short circuit out after at most 2 BCrypt hashes
            if (hashSpec.getHashType() != PasswordType.BCrypt || bcryptCount <= 2) {
                if (hashSpec.getHashType() == PasswordType.BCrypt) bcryptCount++;

                if (hashSpec.getHashType() != null) {
                    String credentialHash = CalcCredentialHash(username, password, accountsResponse.getSalt(), hashSpec);

                    if (credentialHash != null) {
                        if (queryString.length() == 0)
                            queryString.append("?hashes=").append(URLEncoder.encode(credentialHash, "UTF-8"));
                        else
                            queryString.append("&hashes=").append(URLEncoder.encode(credentialHash, "UTF-8"));
                    }
                }
            }
        }

        if (queryString.length() > 0) {
            String credsResponse = MakeRestCall(
                    apiBaseURL + CREDENTIALS_API_PATH + queryString, "GET", null);

            return !credsResponse.equals("404");
        }
        return false;
    }

    /**
     * Checks whether the provided password is in the PasswordPing database of known, compromised passwords.
     * @see <a href="https://www.passwordping.com/docs/passwords-api">https://www.passwordping.com/docs/passwords-api</a>
     * @param password The password to be checked
     * @return If true, the password is a known, compromised password and should not be used.
     * @throws IOException Could not communicate with PasswordPing server.
     * @throws RuntimeException Runtime errors indicated by message
     */
    public boolean CheckPassword(final String password)
            throws IOException, RuntimeException {

        String response = MakeRestCall(
                apiBaseURL + PASSWORDS_API_PATH +
                    "?md5=" + Hashing.md5(password) +
                    "&sha1=" + Hashing.sha1(password) +
                    "&sha256=" + Hashing.sha256(password),
                "GET", null);

        return !response.equals("404");
    }

    /**
     * Returns all of the credentials Exposures that have been found for a given username.
     * @see <a href="https://www.passwordping.com/docs/exposures-api#get-exposures">https://www.passwordping.com/docs/exposures-api#get-exposures</a>
     * @param username The username or email address of the user to check
     * @return The response contains an array of exposure IDs for this user.  These IDs can be used with the GetExposureDetails call to get additional information about each Exposure.
     * @throws IOException Could not communicate with PasswordPing server.
     */
    public ExposuresResponse GetExposuresForUser(final String username)
        throws IOException {
        ExposuresResponse result;

        String response = MakeRestCall(apiBaseURL + EXPOSURES_API_PATH + "?username=" + URLEncoder.encode(username, "UTF-8"),
                "GET", null);

        if (response.equals("404")) {
            // don't have this email in the DB - return empty response
            result = new ExposuresResponse();
        }
        else {
            // deserialize response
            result = new Gson().fromJson(response, ExposuresResponse.class);
        }

        return result;
    }

    /**
     * Returns the detailed information for a credentials Exposure.
     * @see <a href="https://www.passwordping.com/docs/exposures-api#get-exposure-details">https://www.passwordping.com/docs/exposures-api#get-exposure-details</a>
     * @param exposureID The ID of the Exposure
     * @return The response body contains the details of the Exposure or null if the Exposure ID could not be found.
     * @throws IOException Could not communicate with PasswordPing server.
     */
    public ExposureDetails GetExposureDetails(final String exposureID)
            throws IOException {
        ExposureDetails result = null;

        String response = MakeRestCall(apiBaseURL + EXPOSURES_API_PATH + "?id=" + URLEncoder.encode(exposureID, "UTF-8"),
                "GET", null);

        if (!response.equals("404")) {
            // deserialize response
            result = new Gson().fromJson(response, ExposureDetails.class);
        }

        return result;
    }

    private String MakeRestCall(final String restUrl, final String method, final String body)
        throws IOException, RuntimeException {

        URL url = new URL(restUrl);

        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod(method);
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("Authorization", authString);

        int responseStatus = conn.getResponseCode();

        if (responseStatus == 200) {
            return IOUtils.toString(conn.getInputStream(), conn.getContentEncoding());
        }
        else if (responseStatus == 404) {
            return "404";
        }
        else {
            throw new RuntimeException("API Call to " + restUrl + " failed. HTTP error code: " + conn.getResponseCode() + " Message: " + conn.getContent().toString());
        }
    }

    private static ResourceBundle resource = ResourceBundle.getBundle("passwordping");

    private String GetProperty(final String key, final String defaultValue) {
        String result = resource.getString(key);
        if (result == null)
            result = defaultValue;
        return result;
    }

    private String CalcAuthString(final String apiKey, final String secret) {
        return "basic " + Hashing.encodeBase64(apiKey + ":" + secret);
    }

    private String CalcCredentialHash(final String username, final String password, String salt, PasswordHashSpecification specification) {
        String passwordHash = CalcPasswordHash(specification.getHashType(), password, specification.getSalt());

        if (passwordHash != null) {
            String argon2Hash = Hashing.argon2(username + "$" + passwordHash, salt);

            String justHash = argon2Hash.substring(argon2Hash.lastIndexOf('$') + 1);
            return Hashing.bytesToHex(Hashing.decodeBase64(justHash));
        }
        else {
            return null;
        }
    }

    private String CalcPasswordHash(final PasswordType passwordType, final String password, final String salt) {
        switch (passwordType) {
            case MD5:
                return Hashing.md5(password);
            case SHA1:
                return Hashing.sha1(password);
            case SHA256:
                return Hashing.sha256(password);
            case IPBoard_MyBB:
                if (salt != null && salt.length() > 0) {
                    return Hashing.myBB(password, salt);
                }
                return null;
            case vBulletinPre3_8_5:
            case vBulletinPost3_8_5:
                if (salt != null && salt.length() > 0) {
                    return Hashing.vBulletin(password, salt);
                }
                return null;
            case BCrypt:
                if (salt != null && salt.length() > 0) {
                    return Hashing.bCrypt(password, salt);
                }
                return null;
            case CRC32:
                return Hashing.crc32(password);
            case PHPBB3:
                if (salt != null && salt.length() > 0) {
                    return Hashing.phpbb3(password, salt);
                }
                return null;
            case CustomAlgorithm1:
                if (salt != null && salt.length() > 0) {
                    return Hashing.customAlgorithm1(password, salt);
                }
                return null;
            case CustomAlgorithm2:
                if (salt != null && salt.length() > 0) {
                    return Hashing.customAlgorithm2(password, salt);
                }
                return null;
            case SHA512:
                return Hashing.sha512(password);
            case MD5Crypt:
                if (salt != null && salt.length() > 0) {
                    return Hashing.md5Crypt(password, salt);
                }
                return null;
            case CustomAlgorithm4:
                if (salt != null && salt.length() > 0) {
                    return Hashing.customAlgorithm4(password, salt);
                }
                return null;
            default:
                return null;
        }
    }
}
