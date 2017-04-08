package com.passwordping.client;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * These are actually live tests and require a valid API key and Secret to be set in your environment variables.
 * Set an env var for PP_API_KEY and PP_API_SECRET with the respective values prior to running the tests.
 */
class PasswordPingTest {

    @Test
    void checkConstructor() {
        assertTrue(checkConstructorWithParameters(null, null));
        assertTrue(checkConstructorWithParameters("test", null));
        assertTrue(checkConstructorWithParameters(null, "test"));
        assertTrue(checkConstructorWithParameters("", ""));
        assertTrue(checkConstructorWithParameters("", "test"));
        assertTrue(checkConstructorWithParameters("test", ""));
        assertFalse(checkConstructorWithParameters("test", "test"));
    }

    @Test
    void checkCredentials() {
        PasswordPing passwordping = getPasswordPing();

        try {
            boolean exposed = passwordping.CheckCredentials("test@passwordping.com", "123456");
            assertTrue(exposed);

            exposed = passwordping.CheckCredentials("test@passwordping.com", "notvalid");
            assertFalse(exposed);
        }
        catch (java.io.IOException ioException) {
            assertTrue(false, "IO exception reaching API: " + ioException.getMessage());
        }
    }

    @Test
    void getExposures() {
        PasswordPing passwordping = getPasswordPing();

        try {
            ExposuresResponse result = passwordping.GetExposuresForUser("@@bogus-username@@");
            assertTrue(result.getCount() == 0);
            assertTrue(result.getExposures().length == 0);

            result = passwordping.GetExposuresForUser("eicar");
            assertEquals(4, result.getCount());
            assertEquals(4, result.getExposures().length);
            assertArrayEquals(new String[] {"5820469ffdb8780510b329cc", "58258f5efdb8780be88c2c5d", "582a8e51fdb87806acc426ff", "583d2f9e1395c81f4cfa3479"}, result.getExposures());
        }
        catch (Exception ex) {
            assertTrue(false, "Exception calling GetExposuresForUser: " + ex.getMessage());
        }
    }

    @Test
    void getExposureDetails() {
        PasswordPing passwordping = getPasswordPing();

        try {
            ExposureDetails result = passwordping.GetExposureDetails("111111111111111111111111");
            assertEquals(null, result);

            result = passwordping.GetExposureDetails("5820469ffdb8780510b329cc");
            assertTrue(result != null);
            assertEquals("5820469ffdb8780510b329cc", result.getId());
            assertEquals("last.fm", result.getTitle());
            assertEquals("Music", result.getCategory());
            assertEquals(1330560000000L, result.getDate().getTime());
            assertEquals("MD5", result.getPasswordType());
            assertArrayEquals(new String[] { "Emails", "Passwords", "Usernames", "Website Activity"}, result.getExposedData());
            assertEquals(43570999, result.getEntries());
            assertEquals(1218513, result.getDomainsAffected());
        }
        catch (Exception ex) {
            assertTrue(false, "Exception calling GetExposureDetails: " + ex.getMessage());
        }
    }

    @Test
    void checkPassword() {
        PasswordPing passwordping = new PasswordPing(getAPIKey(), getAPISecret());

        try {
            assertFalse(passwordping.CheckPassword("kjdlkjdlksjdlskjdlskjslkjdslkdjslkdjslkd"));
            assertTrue(passwordping.CheckPassword("123456"));
        }
        catch (Exception ex) {
            assertTrue(false, "Exception calling CheckPassword: " + ex.getMessage());
        }
    }

    // HELPER METHODS

    private boolean checkConstructorWithParameters(String apiKey, String secret) {
        try {
            new PasswordPing(apiKey, secret);
        }
        catch (Exception ex) {
            return true;
        }
        return false;
    }

    private PasswordPing getPasswordPing() {
        return new PasswordPing(getAPIKey(), getAPISecret());
    }

    private String getAPIKey() {
        // set these env vars to run live tests
        return System.getenv("PP_API_KEY");
    }

    private String getAPISecret() {
        // set these env vars to run live tests
        return System.getenv("PP_API_SECRET");
    }

}