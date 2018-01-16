package com.passwordping.client;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.lang.reflect.*;

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
    void checkRequestTimeout() {
        PasswordPing passwordping = getPasswordPing();
        assertEquals((Integer)0, passwordping.GetRequestTimeout());
        passwordping.SetRequestTimeout(2);
        assertEquals((Integer)2, passwordping.GetRequestTimeout());

        // now try a request - it should timeout with a value of 2 ms being used
        boolean exception = false;
        try {
            passwordping.CheckCredentials("test@passwordping.com", "123456");
        }
        catch (java.io.IOException ioException) {
            exception = true;
        }
        assertTrue(exception);

        passwordping.SetRequestTimeout(10000);
        assertEquals((Integer)10000, passwordping.GetRequestTimeout());

        // try another request - it should not timeout with a value of 10000 ms being used
        exception = false;
        try {
            passwordping.CheckCredentials("test@passwordping.com", "123456");
        }
        catch (java.io.IOException ioException) {
            exception = true;
        }
        assertFalse(exception);
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
            assertEquals(6, result.getCount());
            assertEquals(6, result.getExposures().length);
            assertArrayEquals(new String[] {"5820469ffdb8780510b329cc", "58258f5efdb8780be88c2c5d", "582a8e51fdb87806acc426ff", "583d2f9e1395c81f4cfa3479", "59ba1aa369644815dcd8683e", "59cae0ce1d75b80e0070957c"}, result.getExposures());
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

    @Test
    void checkCalcPasswordHash() {
        PasswordPing passwordping = new PasswordPing(getAPIKey(), getAPISecret());

        try {
            Class[] args = new Class[3];
            args[0] = PasswordType.class;
            args[1] = String.class;
            args[2] = String.class;
            Method method = PasswordPing.class.getDeclaredMethod("CalcPasswordHash", args);
            method.setAccessible(true);

            assertEquals("e10adc3949ba59abbe56e057f20f883e", method.invoke(passwordping, new Object[] { PasswordType.MD5, "123456", null }));
            assertEquals("7c4a8d09ca3762af61e59520943dc26494f8941b", method.invoke(passwordping, new Object[] { PasswordType.SHA1, "123456", null }));
            assertEquals("8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", method.invoke(passwordping, new Object[] { PasswordType.SHA256, "123456", null }));
            assertEquals("2e705e174e9df3e2c8aaa30297aa6d74", method.invoke(passwordping, new Object[] { PasswordType.IPBoard_MyBB, "123456", ";;!_X" }));
            assertEquals("57ce303cdf1ad28944d43454cea38d7a", method.invoke(passwordping, new Object[] { PasswordType.vBulletinPost3_8_5, "123456789", "]G@" }));
            assertEquals("$2a$12$2bULeXwv2H34SXkT1giCZeJW7A6Q0Yfas09wOCxoIC44fDTYq44Mm", method.invoke(passwordping, new Object[] { PasswordType.BCrypt, "12345", "$2a$12$2bULeXwv2H34SXkT1giCZe" }));
            assertEquals("972d361", method.invoke(passwordping, new Object[] { PasswordType.CRC32, "123456", null }));
            assertEquals("$H$993WP3hbzy0N22X06wxrCc3800D2p41", method.invoke(passwordping, new Object[] { PasswordType.PHPBB3, "123456789", "$H$993WP3hbz" }));
            assertEquals("cee66db36504915f48b2d545803a4494bb1b76b6e9d8ba8c0e6083ff9b281abdef31f6172548fdcde4000e903c5a98a1178c414f7dbf44cffc001aee8e1fe206", method.invoke(passwordping, new Object[] { PasswordType.CustomAlgorithm1, "123456", "00new00" }));
            assertEquals("579d9ec9d0c3d687aaa91289ac2854e4", method.invoke(passwordping, new Object[] { PasswordType.CustomAlgorithm2, "123456", "123" }));
            assertEquals("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff", method.invoke(passwordping, new Object[] { PasswordType.SHA512, "test", null }));
            assertEquals("$1$4d3c09ea$hPwyka2ToWFbLTOq.yFjf.", method.invoke(passwordping, new Object[] { PasswordType.MD5Crypt, "123456", "$1$4d3c09ea" }));
            assertEquals("$2y$12$Yjk3YjIzYWIxNDg0YWMzZOpp/eAMuWCD3UwX1oYgRlC1ci4Al970W", method.invoke(passwordping, new Object[] { PasswordType.CustomAlgorithm4, "1234", "$2y$12$Yjk3YjIzYWIxNDg0YWMzZO" }));
        }
        catch (Exception ex) {
            assertTrue(false, "Exception calling CalcPasswordHash: " + ex.getMessage());
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