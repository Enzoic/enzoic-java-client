package com.enzoic.client;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.lang.reflect.*;
import java.util.Calendar;
import java.util.Date;

/**
 * These are actually live tests and require a valid API key and Secret to be set in your environment variables.
 * Set an env var for PP_API_KEY and PP_API_SECRET with the respective values prior to running the tests.
 */
class EnzoicTest {

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
        Enzoic enzoic = getEnzoic();
        assertEquals((Integer)0, enzoic.GetRequestTimeout());
        enzoic.SetRequestTimeout(2);
        assertEquals((Integer)2, enzoic.GetRequestTimeout());

        // now try a request - it should timeout with a value of 2 ms being used
        boolean exception = false;
        try {
            enzoic.CheckCredentials("test@passwordping.com", "123456");
        }
        catch (java.io.IOException ioException) {
            exception = true;
        }
        assertTrue(exception);

        enzoic.SetRequestTimeout(10000);
        assertEquals((Integer)10000, enzoic.GetRequestTimeout());

        // try another request - it should not timeout with a value of 10000 ms being used
        exception = false;
        try {
            enzoic.CheckCredentials("test@passwordping.com", "123456");
        }
        catch (java.io.IOException ioException) {
            exception = true;
        }
        assertFalse(exception);
    }

    @Test
    void checkCredentials() {
        Enzoic enzoic = getEnzoic();

        try {
            boolean exposed = enzoic.CheckCredentials("test@passwordping.com", "123456");
            assertTrue(exposed);

            exposed = enzoic.CheckCredentials("test@passwordping.com", "notvalid");
            assertFalse(exposed);
        }
        catch (java.io.IOException ioException) {
            fail("IO exception reaching API: " + ioException.getMessage());
        }
    }

    @Test
    void checkCredentialsEx() {
        Enzoic enzoic = getEnzoic();

        try {
            boolean exposed = enzoic.CheckCredentialsEx("testpwdpng445", "testpwdpng4452", null, null);
            assertTrue(exposed);

            exposed = enzoic.CheckCredentialsEx("testpwdpng445", "notvalid", null, null);
            assertFalse(exposed);

            // make sure we don't get a positive response if the last check date is after the last breach date
            exposed = enzoic.CheckCredentialsEx("testpwdpng445", "testpwdpng4452", new Date(2018, Calendar.APRIL, 1, 0, 0), null);
            assertFalse(exposed);

            // now try by excluding the only valid password hash for this one and make sure we don't get a positive response
            exposed = enzoic.CheckCredentialsEx("testpwdpng445", "testpwdpng4452", null, new PasswordType[] { PasswordType.vBulletinPost3_8_5 });
            assertFalse(exposed);

            // one with a bad salt
            exposed = enzoic.CheckCredentialsEx("eicar_8@enzoic.com", "123456", null, null);
            assertTrue(exposed);
        }
        catch (java.io.IOException ioException) {
            fail("IO exception reaching API: " + ioException.getMessage());
        }
    }

    @Test
    void getExposures() {
        Enzoic enzoic = getEnzoic();

        try {
            ExposuresResponse result = enzoic.GetExposuresForUser("@@bogus-username@@");
            assertEquals(0, result.getCount());
            assertEquals(0, result.getExposures().length);

            result = enzoic.GetExposuresForUser("eicar");
            assertEquals(8, result.getCount());
            assertEquals(8, result.getExposures().length);
            assertArrayEquals(new String[] {"5820469ffdb8780510b329cc", "58258f5efdb8780be88c2c5d", "582a8e51fdb87806acc426ff", "583d2f9e1395c81f4cfa3479", "59ba1aa369644815dcd8683e", "59cae0ce1d75b80e0070957c", "5bc64f5f4eb6d894f09eae70", "5bdcb0944eb6d8a97cfacdff"}, result.getExposures());
        }
        catch (Exception ex) {
            fail("Exception calling GetExposuresForUser: " + ex.getMessage());
        }
    }

    @Test
    void getExposureDetails() {
        Enzoic enzoic = getEnzoic();

        try {
            ExposureDetails result = enzoic.GetExposureDetails("111111111111111111111111");
            assertNull(result);

            result = enzoic.GetExposureDetails("5820469ffdb8780510b329cc");
            assertNotNull(result);
            assertEquals("5820469ffdb8780510b329cc", result.getId());
            assertEquals("last.fm", result.getTitle());
            assertEquals("Music", result.getCategory());
            assertEquals(1330560000000L, result.getDate().getTime());
            assertEquals("MD5", result.getPasswordType());
            assertArrayEquals(new String[] { "Emails", "Passwords", "Usernames", "Website Activity"}, result.getExposedData());
            assertEquals(81967007, result.getEntries());
            assertEquals(1219053, result.getDomainsAffected());
        }
        catch (Exception ex) {
            fail("Exception calling GetExposureDetails: " + ex.getMessage());
        }
    }

    @Test
    void checkPassword() {
        Enzoic enzoic = getEnzoic();

        try {
            assertFalse(enzoic.CheckPassword("kjdlkjdlksjdlskjdlskjslkjdslkdjslkdjslkd"));
            assertTrue(enzoic.CheckPassword("123456"));
        }
        catch (Exception ex) {
            fail("Exception calling CheckPassword: " + ex.getMessage());
        }
    }

    @Test
    void checkPasswordEx() {
        Enzoic enzoic = getEnzoic();

        try {
            CheckPasswordExResponse response = enzoic.CheckPasswordEx("kjdlkjdlksjdlskjdlskjslkjdslkdjslkdjslkd");
            assertNull(response);
            response = enzoic.CheckPasswordEx("123456");
            assertTrue(response.isRevealedInExposure());
            assertTrue(response.exposureCount() > 10);
            response = enzoic.CheckPasswordEx("password");
            assertTrue(response.isRevealedInExposure());
            assertTrue(response.exposureCount() > 10);
            response = enzoic.CheckPasswordEx("``--...____...--''");
            assertFalse(response.isRevealedInExposure());
            assertEquals(0, response.relativeExposureFrequency());
            assertEquals(0, response.exposureCount());
        }
        catch (Exception ex) {
            fail("Exception calling CheckPasswordEx: " + ex.getMessage());
        }
    }

    @Test
    void checkCalcPasswordHash() {
        Enzoic enzoic = getEnzoic();

        try {
            Class[] args = new Class[3];
            args[0] = PasswordType.class;
            args[1] = String.class;
            args[2] = String.class;
            Method method = Enzoic.class.getDeclaredMethod("CalcPasswordHash", args);
            method.setAccessible(true);

            assertEquals("e10adc3949ba59abbe56e057f20f883e", method.invoke(enzoic, PasswordType.MD5, "123456", null));
            assertEquals("7c4a8d09ca3762af61e59520943dc26494f8941b", method.invoke(enzoic, PasswordType.SHA1, "123456", null));
            assertEquals("8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", method.invoke(enzoic, PasswordType.SHA256, "123456", null));
            assertEquals("2e705e174e9df3e2c8aaa30297aa6d74", method.invoke(enzoic, PasswordType.IPBoard_MyBB, "123456", ";;!_X"));
            assertEquals("57ce303cdf1ad28944d43454cea38d7a", method.invoke(enzoic, PasswordType.vBulletinPost3_8_5, "123456789", "]G@"));
            assertEquals("$2a$12$2bULeXwv2H34SXkT1giCZeJW7A6Q0Yfas09wOCxoIC44fDTYq44Mm", method.invoke(enzoic, PasswordType.BCrypt, "12345", "$2a$12$2bULeXwv2H34SXkT1giCZe"));
            assertEquals("972d361", method.invoke(enzoic, PasswordType.CRC32, "123456", null));
            assertEquals("$H$993WP3hbzy0N22X06wxrCc3800D2p41", method.invoke(enzoic, PasswordType.PHPBB3, "123456789", "$H$993WP3hbz"));
            assertEquals("cee66db36504915f48b2d545803a4494bb1b76b6e9d8ba8c0e6083ff9b281abdef31f6172548fdcde4000e903c5a98a1178c414f7dbf44cffc001aee8e1fe206", method.invoke(enzoic, PasswordType.CustomAlgorithm1, "123456", "00new00"));
            assertEquals("579d9ec9d0c3d687aaa91289ac2854e4", method.invoke(enzoic, PasswordType.CustomAlgorithm2, "123456", "123"));
            assertEquals("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff", method.invoke(enzoic, PasswordType.SHA512, "test", null));
            assertEquals("$1$4d3c09ea$hPwyka2ToWFbLTOq.yFjf.", method.invoke(enzoic, PasswordType.MD5Crypt, "123456", "$1$4d3c09ea"));
            assertEquals("$2y$12$Yjk3YjIzYWIxNDg0YWMzZOpp/eAMuWCD3UwX1oYgRlC1ci4Al970W", method.invoke(enzoic, PasswordType.CustomAlgorithm4, "1234", "$2y$12$Yjk3YjIzYWIxNDg0YWMzZO"));
            assertEquals("69e7ade919a318d8ecf6fd540bad9f169bce40df4cae4ac1fb6be2c48c514163", method.invoke(enzoic, PasswordType.CustomAlgorithm5, "password", "123456"));
            assertEquals("d2bc2f8d09990ebe87c809684fd78c66", method.invoke(enzoic, PasswordType.osCommerce_AEF, "password", "123"));
            assertEquals("yDba8kDA7NUDQ", method.invoke(enzoic, PasswordType.DESCrypt, "qwerty", "yD"));
            assertEquals("5d2e19393cc5ef67", method.invoke(enzoic, PasswordType.MySQLPre4_1, "password", null));
            assertEquals("*94bdcebe19083ce2a1f959fd02f964c7af4cfc29", method.invoke(enzoic, PasswordType.MySQLPost4_1, "test", null));
            assertEquals("3weP/BR8RHPLP2459h003IgJxyU=", method.invoke(enzoic, PasswordType.PeopleSoft, "TESTING", null));
            assertEquals("0c9a0dc3dd0b067c016209fd46749c281879069e", method.invoke(enzoic, PasswordType.PunBB, "password", "123"));
            assertEquals("5f4dcc3b5aa765d61d83", method.invoke(enzoic, PasswordType.PartialMD5_20, "password", null));
            assertEquals("696d29e0940a4957748fe3fc9efd22a3", method.invoke(enzoic, PasswordType.AVE_DataLife_Diferior, "password", null));
            assertEquals("md5$c6218$346abd81f2d88b4517446316222f4276", method.invoke(enzoic, PasswordType.DjangoMD5, "password", "c6218"));
            assertEquals("sha1$c6218$161d1ac8ab38979c5a31cbaba4a67378e7e60845", method.invoke(enzoic, PasswordType.DjangoSHA1, "password", "c6218"));
            assertEquals("5f4dcc3b5aa765d61d8327deb882c", method.invoke(enzoic, PasswordType.PartialMD5_29, "password", null));
            assertEquals("1230de084f38ace8e3d82597f55cc6ad5d6001568e6", method.invoke(enzoic, PasswordType.PliggCMS, "password", "123"));
            assertEquals("0de084f38ace8e3d82597f55cc6ad5d6001568e6", method.invoke(enzoic, PasswordType.RunCMS_SMF1_1, "password", "123"));
            assertEquals("32ed87bdb5fdc5e9cba88547376818d4", method.invoke(enzoic, PasswordType.NTLM, "123456", null));
            assertEquals("55566a759b86fbbd979b579b232f4dd214d08068", method.invoke(enzoic, PasswordType.SHA1Dash, "123456", "478c8029d5efddc554bf2fe6bb2219d8c897d4a0"));
            assertEquals("0a989ebc4a77b56a6e2bb7b19d995d185ce44090c13e2984b7ecc6d446d4b61ea9991b76a4c2f04b1b4d244841449454", method.invoke(enzoic, PasswordType.SHA384, "123456", null));
            assertEquals("a753d386613efd6d4a534cec97e73890f8ec960fe6634db6dbfb9b2aab207982", method.invoke(enzoic, PasswordType.CustomAlgorithm7, "123456", "123456"));
            assertEquals("9fc389447b7eb88aff45a1069bf89fbeff89b8fb7d11a6f450583fa4c9c70503", method.invoke(enzoic, PasswordType.CustomAlgorithm8, "matthew", "Dn"));
            assertEquals("07c691fa8b022b52ac1c44cab3e056b344a7945b6eb9db727e3842b28d94fe18c17fe5b47b1b9a29d8149acbd7b3f73866cc12f0a8a8b7ab4ac9470885e052dc", method.invoke(enzoic, PasswordType.CustomAlgorithm9, "0rangepeel", "6kpcxVSjagLgsNCUCr-D"));
            assertEquals("$5$rounds=5000$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD", method.invoke(enzoic, PasswordType.SHA256Crypt, "hashcat", "$5$rounds=5000$GX7BopJZJxPc/KEK"));
            assertEquals("$SHA$7218532375810603$bfede293ecf6539211a7305ea218b9f3f608953130405cda9eaba6fb6250f824", method.invoke(enzoic, PasswordType.AuthMeSHA256, "hashcat", "7218532375810603"));
            assertEquals("d89c92b4400b15c39e462a8caa939ab40c3aeeea", method.invoke(enzoic, PasswordType.HMACSHA1_SaltAsKey, "hashcat", "1234"));
        }
        catch (Exception ex) {
            fail("Exception calling CalcPasswordHash: " + ex.getMessage());
        }
    }

    @Test
    void getUserPasswords() {
        Enzoic enzoic = getEnzoic();

        try {
            UserPasswords result = enzoic.GetUserPasswords("enzoic_not_found@enzoic.com");
            assertNull(result);

            result = enzoic.GetUserPasswords("eicar_0@enzoic.com");
            assertNotNull(result);
            assertEquals(new Date(1665730960000L), result.getLastBreachDate());
            assertEquals(PasswordType.Plaintext, result.getPasswords()[0].getHashType());
            assertEquals("password123", result.getPasswords()[0].getPassword());
            assertEquals("", result.getPasswords()[0].getSalt());
            assertArrayEquals(new String[] { "634908d2e0513eb0788aa0b9", "634908d06715cc1b5b201a1a"}, result.getPasswords()[0].getExposures());

            assertEquals(PasswordType.Plaintext, result.getPasswords()[3].getHashType());
            assertEquals("123456", result.getPasswords()[3].getPassword());
            assertEquals("", result.getPasswords()[3].getSalt());
            assertArrayEquals(new String[] { "63490990e0513eb0788aa0d1", "634908d0e0513eb0788aa0b5"}, result.getPasswords()[3].getExposures());

            result = enzoic.GetUserPasswords("eicar_0@enzoic.com", true);
            assertNotNull(result);
            assertEquals(new Date(1665730960000L), result.getLastBreachDate());
            assertEquals(PasswordType.Plaintext, result.getPasswords()[0].getHashType());
            assertEquals("password123", result.getPasswords()[0].getPassword());
            assertEquals("", result.getPasswords()[0].getSalt());
            assertArrayEquals(new String[] { "634908d2e0513eb0788aa0b9", "634908d06715cc1b5b201a1a"}, result.getPasswords()[0].getExposures());

            assertEquals(PasswordType.Plaintext, result.getPasswords()[3].getHashType());
            assertEquals("123456", result.getPasswords()[3].getPassword());
            assertEquals("", result.getPasswords()[3].getSalt());
            assertArrayEquals(new String[] { "63490990e0513eb0788aa0d1", "634908d0e0513eb0788aa0b5"}, result.getPasswords()[3].getExposures());

            // try an account with no permissions
            try {
                enzoic = new Enzoic(getAPIKey2(), getAPISecret2());
                result = enzoic.GetUserPasswords("eicar_0@enzoic.com");
                fail("GetUserPasswords should fail and return exception for accounts which do not have permissions");
            }
            catch (Exception ex) {
                assertTrue(ex.getMessage().startsWith("Server returned HTTP response code: 403"));
            }
        }
        catch (Exception ex) {
            fail("Exception calling GetUserPasswords: " + ex.getMessage());
        }
    }

    // HELPER METHODS

    private boolean checkConstructorWithParameters(String apiKey, String secret) {
        try {
            new Enzoic(apiKey, secret);
        }
        catch (Exception ex) {
            return true;
        }
        return false;
    }

    private Enzoic getEnzoic() {
        return new Enzoic(getAPIKey(), getAPISecret());
    }

    private String getAPIKey() {
        // set these env vars to run live tests
        return System.getenv("PP_API_KEY");
    }

    private String getAPISecret() {
        // set these env vars to run live tests
        return System.getenv("PP_API_SECRET");
    }

    private String getAPIKey2() {
        // set these env vars to run live tests
        return System.getenv("PP_API_KEY_2");
    }

    private String getAPISecret2() {
        // set these env vars to run live tests
        return System.getenv("PP_API_SECRET_2");
    }
}