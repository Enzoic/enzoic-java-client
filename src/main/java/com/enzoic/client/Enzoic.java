package com.enzoic.client;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.ResourceBundle;
import java.util.Date;
import com.google.gson.Gson;
import org.apache.commons.io.IOUtils;
import com.enzoic.client.utilities.Hashing;

/**
 * This is the main entry point for accessing Enzoic.
 *
 * Create this class with your API Key and Secret and then call the desired methods on the class
 * to access the Enzoic API.
 */
public class Enzoic {

    private static final String CREDENTIALS_API_PATH = "/credentials";
    private static final String PASSWORDS_API_PATH = "/passwords";
    private static final String EXPOSURES_API_PATH = "/exposures";
    private static final String ACCOUNTS_API_PATH = "/accounts";
    private static final String ALERTS_SERVICE_PATH = "/alert-subscriptions";

    private String apiKey;
    private String secret;
    private String authString;
    private String apiBaseURL;
    private Integer requestTimeout = 0;

    /**
     * Creates a new instance of Enzoic
     * @param apiKey your Enzoic API key
     * @param secret your Enzoic API secret
     */
    public Enzoic(final String apiKey, final String secret) {
        this(apiKey, secret, null);
    }

    /**
     * Creates a new instance of Enzoic
     * @param apiKey your Enzoic API key
     * @param secret your Enzoic API secret
     * @param apiBaseURL override the default base API URL with an alternate - typically not necessary
     */
    public Enzoic(final String apiKey, final String secret, final String apiBaseURL) {
        if (apiKey == null || apiKey.length() == 0) {
            throw new IllegalArgumentException("API Key cannot be null or empty");
        }

        if (secret == null || secret.length() == 0) {
            throw new IllegalArgumentException("Secret cannot be null or empty");
        }

        String baseURL = apiBaseURL;
        if (baseURL == null || baseURL.length() == 0) {
            baseURL = GetProperty("defaultAPIBaseURL", "https://api.enzoic.com/v1");
        }

        this.apiKey = apiKey;
        this.secret = secret;
        this.apiBaseURL = baseURL;
        this.authString = CalcAuthString(apiKey, secret);
    }

    /**
     * Sets a timeout value for requests made to the Enzoic API.
     * @param timeoutInMs The timeout value in milliseconds to use.  0 indicates a timeout of infinity will be used.
     */
    public void SetRequestTimeout(final Integer timeoutInMs) {
        this.requestTimeout = timeoutInMs;
    }

    /**
     * Gets the current request timeout value being used for making requests to the Enzoic API.
     * @return The timeout value in milliseconds being used.  0 indicates a timeout of infinity.
     */
    public Integer GetRequestTimeout() {
        return this.requestTimeout;
    }

    /**
     * Calls the Enzoic CheckCredentials API in a secure fashion to check whether the provided username and password
     * are known to be compromised.
     * This call is made securely to the server - only a salted and hashed representation of the credentials are passed and
     * the salt value is not passed along with it.
     * @see <a href="https://www.enzoic.com/docs/credentials-api">https://www.enzoic.com/docs/credentials-api</a>
     * @param username the username to check
     * @param password the password to check
     * @return if true, then the credentials are known to be compromised
     * @throws IOException Could not communicate with Enzoic server.
     * @throws RuntimeException Runtime errors indicated by message
     */
    public boolean CheckCredentials(final String username, final String password)
            throws IOException, RuntimeException {
        return CheckCredentialsEx(username, password, null, null);
    }

    /**
     * Calls the Enzoic CheckCredentials API in a secure fashion to check whether the provided username and password
     * are known to be compromised.
     * This call is made securely to the server - only a salted and hashed representation of the credentials are passed and
     * the salt value is not passed along with it.
     * The Ex version of the call includes additional parameters that allow the client to tweak the performance of the call.
     *
     * lastCheckDate allows the caller to pass in the date of the last check that was made for the credentials in question.
     * If the lastCheckDate is after the last new breach that was recorded for those credentials, there is no need to check them again
     * and no hashes will be calculated and no credentials API call will be made.  This can substantially improve performance.
     * Note that for this to work, the calling application will need to cache the date/time the last credentials check was
     * made for a given set of user credentials and invalidate reset that date/time if the credentials are changed.
     *
     * excludeHashTypes allows the calling application to exclude certain expensive password hash algorithms from being
     * calculated (e.g. BCrypt).  This can reduce the CPU impact of the call as well as potentially decrease the latency
     * it introduces.
     *
     * @see <a href="https://www.enzoic.com/docs/credentials-api">https://www.enzoic.com/docs/credentials-api</a>
     * @param username the username to check
     * @param password the password to check
     * @param lastCheckDate The timestamp for the last check you performed for this user.  If the date/time you provide
     *                      for the last check is greater than the timestamp Enzoic has for the last breach
     *                      affecting this user, the check will not be performed.  This can be used to substantially
     *                      increase performance.  Can be set to null if no last check was performed or the credentials
     *                      have changed since.
     * @param excludeHashTypes  An array of PasswordTypes to ignore when calculating hashes for the credentials check.
     *                          By excluding computationally expensive PasswordTypes, such as BCrypt, it is possible to
     *                          balance the performance of this call against security.  Can be set to null if you don't
     *                          wish to exclude any hash types.
     * @return if true, then the credentials are known to be compromised
     * @throws IOException Could not communicate with Enzoic server.
     * @throws RuntimeException Runtime errors indicated by message
     */
    public boolean CheckCredentialsEx(final String username, final String password, final Date lastCheckDate,
                                      final PasswordType excludeHashTypes[])
            throws IOException, RuntimeException {

        PasswordType[] excludedHashTypes = excludeHashTypes;
        if (excludedHashTypes == null) {
            excludedHashTypes = new PasswordType[0];
        }

        Date lastCheckedDate = lastCheckDate == null ? new Date(0) : lastCheckDate;

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

        // see if the lastCheckDate was later than the lastBreachDate - if so bail out
        if (lastCheckedDate.after(accountsResponse.getLastBreachDate())) {
            return false;
        }

        // loop through the hashes required
        ArrayList<PasswordHashSpecification> hashesRequired = new ArrayList<PasswordHashSpecification>();
        hashesRequired.addAll(Arrays.asList(accountsResponse.getPasswordHashesRequired()));

        //String queryString = "";
        int bcryptCount = 0;

        ArrayList<String> credentialHashes = new ArrayList<String>();
        StringBuilder queryString = new StringBuilder();
        for (int i = 0 ; i < Math.min(50, hashesRequired.size()); i++) {
            PasswordHashSpecification hashSpec = hashesRequired.get(i);

            if (Arrays.asList(excludedHashTypes).contains(hashSpec.getHashType())) {
                // skip this one
                continue;
            }

            // bcrypt gets far too expensive for good response time if there are many of them to calculate.
            // some mostly garbage accounts have accumulated a number of them in our DB and if we happen to hit one it
            // kills performance, so short circuit out after at most 2 BCrypt hashes
            if (hashSpec.getHashType() != PasswordType.BCrypt || bcryptCount <= 2) {
                if (hashSpec.getHashType() == PasswordType.BCrypt) bcryptCount++;

                if (hashSpec.getHashType() != null) {
                    String credentialHash = CalcCredentialHash(username, password, accountsResponse.getSalt(), hashSpec);

                    if (credentialHash != null) {
                        credentialHashes.add(credentialHash);
                        if (queryString.length() == 0)
                            queryString.append("?partialHashes=").append(URLEncoder.encode(credentialHash.substring(0, 10), "UTF-8"));
                        else
                            queryString.append("&partialHashes=").append(URLEncoder.encode(credentialHash.substring(0, 10), "UTF-8"));
                    }
                }
            }
        }

        if (queryString.length() > 0) {
            String credsResponse = MakeRestCall(
                    apiBaseURL + CREDENTIALS_API_PATH + queryString, "GET", null);

            if (!credsResponse.equals("404")) {
                CheckCredentialsPartialHashesResponse parsedResponse =
                        new Gson().fromJson(credsResponse, CheckCredentialsPartialHashesResponse.class);

                for (int i = 0; i < parsedResponse.candidateHashes().length; i++) {
                    if (credentialHashes.contains(parsedResponse.candidateHashes()[i])) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Checks whether the provided password is in the Enzoic database of known, compromised passwords.
     * @see <a href="https://www.enzoic.com/docs/passwords-api">https://www.enzoic.com/docs/passwords-api</a>
     * @param password The password to be checked
     * @return If true, the password is a known, compromised password and should not be used.
     * @throws IOException Could not communicate with Enzoic server.
     * @throws RuntimeException Runtime errors indicated by message
     */
    public boolean CheckPassword(final String password)
            throws IOException, RuntimeException {
        return CheckPasswordEx(password) != null;
    }

    /**
     * Checks whether the provided password is in the Enzoic database of known, compromised passwords.  Returns extended
     * information about the compromised status of the password.
     * @see <a href="https://www.enzoic.com/docs/passwords-api">https://www.enzoic.com/docs/passwords-api</a>
     * @param password The password to be checked
     * @return If compromised, returns a CheckPasswordExResponse containing details of the compromised status of the password.
     *   Otherwise returns null.
     * @throws IOException Could not communicate with Enzoic server.
     * @throws RuntimeException Runtime errors indicated by message
     */
    public CheckPasswordExResponse CheckPasswordEx(final String password)
            throws IOException, RuntimeException {

        String md5 = Hashing.md5(password);
        String sha1 = Hashing.sha1(password);
        String sha256 = Hashing.sha256(password);

        String response = MakeRestCall(
                apiBaseURL + PASSWORDS_API_PATH +
                        "?partial_md5=" + md5.substring(0, 10) +
                        "&partial_sha1=" + sha1.substring(0, 10) +
                        "&partial_sha256=" + sha256.substring(0, 10),
                "GET", null);

        if (!response.equals("404")) {
            CheckPasswordPartialHashesResponse parsedResponse =
                    new Gson().fromJson(response, CheckPasswordPartialHashesResponse.class);

            for (int i = 0; i < parsedResponse.candidates().length; i++) {
                if (parsedResponse.candidates()[i].md5().equals(md5) ||
                        parsedResponse.candidates()[i].sha1().equals(sha1) ||
                        parsedResponse.candidates()[i].sha256().equals(sha256)) {
                    return new CheckPasswordExResponse(parsedResponse.candidates()[i].isRevealedInExposure(), parsedResponse.candidates()[i].relativeExposureFrequency());
                }
            }
        }

        return null;
    }

    /**
     * Returns all of the credentials Exposures that have been found for a given username.
     * @see <a href="https://www.enzoic.com/docs/exposures-api#get-exposures">https://www.enzoic.com/docs/exposures-api#get-exposures</a>
     * @param username The username or email address of the user to check
     * @return The response contains an array of exposure IDs for this user.  These IDs can be used with the GetExposureDetails call to get additional information about each Exposure.
     * @throws IOException Could not communicate with Enzoic server.
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
     * Returns the detailed information for a credentials Exposure.  The responses to this call can and should be cached
     * to limit the number of calls made.  The Exposure details are not typically expected to change over time, so they
     * can be cached for relatively long periods of time, e.g. for up to 30 days.
     * @see <a href="https://www.enzoic.com/docs/exposures-api#get-exposure-details">https://www.enzoic.com/docs/exposures-api#get-exposure-details</a>
     * @param exposureID The ID of the Exposure
     * @return The response body contains the details of the Exposure or null if the Exposure ID could not be found.
     * @throws IOException Could not communicate with Enzoic server.
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
        conn.setConnectTimeout(this.requestTimeout);
        conn.setReadTimeout(this.requestTimeout);
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

    private static ResourceBundle resource = ResourceBundle.getBundle("enzoic");

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
            case CustomAlgorithm5:
                if (salt != null && salt.length() > 0) {
                    return Hashing.customAlgorithm5(password, salt);
                }
                return null;
            case osCommerce_AEF:
                if (salt != null && salt.length() > 0) {
                    return Hashing.osCommerce_AEF(password, salt);
                }
                return null;
            case DESCrypt:
                if (salt != null && salt.length() > 0) {
                    return Hashing.desCrypt(password, salt);
                }
                return null;
            case MySQLPre4_1:
                return Hashing.mySQLPre4_1(password);
            case MySQLPost4_1:
                return Hashing.mySQLPost4_1(password);
            case PeopleSoft:
                return Hashing.peopleSoft(password);
            case PunBB:
                if (salt != null && salt.length() > 0) {
                    return Hashing.punBB(password, salt);
                }
                return null;
            case PartialMD5_20:
                return Hashing.md5(password).substring(0, 20);
            case AVE_DataLife_Diferior:
                return Hashing.ave_DataLife_Diferior(password);
            case DjangoMD5:
                if (salt != null && salt.length() > 0) {
                    return Hashing.djangoMD5(password, salt);
                }
                return null;
            case DjangoSHA1:
                if (salt != null && salt.length() > 0) {
                    return Hashing.djangoSHA1(password, salt);
                }
                return null;
            case PartialMD5_29:
                return Hashing.md5(password).substring(0, 29);
            case PliggCMS:
                if (salt != null && salt.length() > 0) {
                    return Hashing.pliggCMS(password, salt);
                }
                return null;
            case RunCMS_SMF1_1:
                if (salt != null && salt.length() > 0) {
                    return Hashing.runCMS_SMF1_1(password, salt);
                }
                return null;
            default:
                return null;
        }
    }
}
