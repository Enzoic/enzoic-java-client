package com.enzoic.client.utilities;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class HashingTest {
    @Test
    void md5() {
        assertEquals("e10adc3949ba59abbe56e057f20f883e", Hashing.md5("123456"));
    }

    @Test
    void sha1() {
        assertEquals("7c4a8d09ca3762af61e59520943dc26494f8941b", Hashing.sha1("123456"));
    }

    @Test
    void sha256() {
        assertEquals("8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", Hashing.sha256("123456"));
    }

    @Test
    void sha512() {
        assertEquals("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff", Hashing.sha512("test"));
    }

    @Test
    void whirlpool() {
        assertEquals("fd9d94340dbd72c11b37ebb0d2a19b4d05e00fd78e4e2ce8923b9ea3a54e900df181cfb112a8a73228d1f3551680e2ad9701a4fcfb248fa7fa77b95180628bb2", Hashing.whirlpool("123456"));
    }

    @Test
    void mybb() {
        assertEquals("2e705e174e9df3e2c8aaa30297aa6d74", Hashing.myBB("123456", ";;!_X"));
    }

    @Test
    void vBulletin() {
        assertEquals("57ce303cdf1ad28944d43454cea38d7a", Hashing.vBulletin("123456789", "]G@"));
    }

    @Test
    void bCrypt() {
        assertEquals("$2a$12$2bULeXwv2H34SXkT1giCZeJW7A6Q0Yfas09wOCxoIC44fDTYq44Mm", Hashing.bCrypt("12345", "$2a$12$2bULeXwv2H34SXkT1giCZe"));
    }

    @Test
    void customAlgorithm1() {
        assertEquals("cee66db36504915f48b2d545803a4494bb1b76b6e9d8ba8c0e6083ff9b281abdef31f6172548fdcde4000e903c5a98a1178c414f7dbf44cffc001aee8e1fe206", Hashing.customAlgorithm1("123456", "00new00"));
    }

    @Test
    void customAlgorithm2() {
        assertEquals("579d9ec9d0c3d687aaa91289ac2854e4", Hashing.customAlgorithm2("123456", "123"));
    }

    @Test void phpbb3() {
        assertEquals("$H$993WP3hbzy0N22X06wxrCc3800D2p41", Hashing.phpbb3("123456789", "$H$993WP3hbz"));
    }

    @Test void argon2() {
        assertEquals("$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0$EklGIPtCSWb3IS+q4IQ7rwrwm2o", Hashing.argon2("123456", "saltysalt"));
        assertEquals("$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0$EklGIPtCSWb3IS+q4IQ7rwrwm2o", Hashing.argon2("123456", "$argon2d$v=19$m=1024,t=3,p=2,l=20$c2FsdHlzYWx0"));
        assertEquals("$argon2i$v=19$m=1024,t=2,p=2$c29tZXNhbHQ$bBKumUNszaveOgEhcaWl6r6Y91Y", Hashing.argon2("password", "$argon2i$v=19$m=1024,t=2,p=2,l=20$c29tZXNhbHQ"));
        assertEquals("$argon2i$v=19$m=4096,t=2,p=4$c29tZXNhbHQ$M2X6yo+ZZ8ROwC7MB6/+1yMhGytTzDczBMgo3Is7ptY", Hashing.argon2("password", "$argon2i$v=19$m=4096,t=2,p=4,l=32$c29tZXNhbHQ"));
        assertEquals("$argon2i$v=19$m=4096,t=2,p=4$c29tZXNhbHQ$ZPidoNOWM3jRl0AD+3mGdZsq+GvHprGL", Hashing.argon2("password", "$argon2i$v=19$m=4096,t=2,p=4,l=24$c29tZXNhbHQ"));

        assertEquals("$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0$EklGIPtCSWb3IS+q4IQ7rwrwm2o", Hashing.argon2("123456", "$argon2d$v=19$m=10d4,t=ejw,p=2$c2FsdHlzYWx0"));
    }

    @Test
    void crc32() {
        assertEquals("972d361", Hashing.crc32("123456"));
    }

    @Test
    void md5Crypt() { assertEquals("$1$4d3c09ea$hPwyka2ToWFbLTOq.yFjf.", Hashing.md5Crypt("123456", "$1$4d3c09ea")); }

    @Test
    void customAlgorithm4() { assertEquals("$2y$12$Yjk3YjIzYWIxNDg0YWMzZOpp/eAMuWCD3UwX1oYgRlC1ci4Al970W", Hashing.customAlgorithm4("1234", "$2y$12$Yjk3YjIzYWIxNDg0YWMzZO")); }

    @Test
    void customAlgorithm5() { assertEquals("69e7ade919a318d8ecf6fd540bad9f169bce40df4cae4ac1fb6be2c48c514163", Hashing.customAlgorithm5("password", "123456")); }

    @Test
    void osCommerce_AEF() { assertEquals("d2bc2f8d09990ebe87c809684fd78c66", Hashing.osCommerce_AEF("password", "123")); }

    @Test
    void desCrypt() { assertEquals("yDba8kDA7NUDQ", Hashing.desCrypt("qwerty", "yD")); }

    @Test
    void mySQLPre4_1() { assertEquals("5d2e19393cc5ef67", Hashing.mySQLPre4_1("password")); }

    @Test
    void mySQLPost4_1() { assertEquals("*94bdcebe19083ce2a1f959fd02f964c7af4cfc29", Hashing.mySQLPost4_1("test")); }

    @Test
    void peopleSoft() { assertEquals("3weP/BR8RHPLP2459h003IgJxyU=", Hashing.peopleSoft("TESTING")); }

    @Test
    void punBB() { assertEquals("0c9a0dc3dd0b067c016209fd46749c281879069e", Hashing.punBB("password", "123")); }

    @Test
    void ave_DataLife_Diferior() { assertEquals("696d29e0940a4957748fe3fc9efd22a3", Hashing.ave_DataLife_Diferior("password")); }

    @Test
    void djangoMD5() { assertEquals("md5$c6218$346abd81f2d88b4517446316222f4276", Hashing.djangoMD5("password", "c6218")); }

    @Test
    void djangoSHA1() { assertEquals("sha1$c6218$161d1ac8ab38979c5a31cbaba4a67378e7e60845", Hashing.djangoSHA1("password", "c6218")); }

    @Test
    void pliggCMS() { assertEquals("1230de084f38ace8e3d82597f55cc6ad5d6001568e6", Hashing.pliggCMS("password", "123")); }

    @Test
    void runCMS_SMF1_1() { assertEquals("0de084f38ace8e3d82597f55cc6ad5d6001568e6", Hashing.runCMS_SMF1_1("password", "123")); }

    @Test
    void ntlm() { assertEquals("32ed87bdb5fdc5e9cba88547376818d4", Hashing.ntlm("123456")); }

    @Test
    void sha384() { assertEquals("0a989ebc4a77b56a6e2bb7b19d995d185ce44090c13e2984b7ecc6d446d4b61ea9991b76a4c2f04b1b4d244841449454", Hashing.sha384("123456")); }

    @Test
    void customAlgorithm7() { assertEquals("a753d386613efd6d4a534cec97e73890f8ec960fe6634db6dbfb9b2aab207982", Hashing.customAlgorithm7("123456", "123456")); }

    @Test
    void customAlgorithm9() { assertEquals("07c691fa8b022b52ac1c44cab3e056b344a7945b6eb9db727e3842b28d94fe18c17fe5b47b1b9a29d8149acbd7b3f73866cc12f0a8a8b7ab4ac9470885e052dc", Hashing.customAlgorithm9("0rangepeel", "6kpcxVSjagLgsNCUCr-D")); }

    @Test
    void sha512Crypt() {
        assertEquals("$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/", Hashing.sha512Crypt("hashcat", "$6$52450745"));
        assertEquals("$6$rounds=5000$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/", Hashing.sha512Crypt("hashcat", "$6$rounds=5000$52450745"));
        assertEquals("$6$rounds=4000$52450745$SpwN1flz4M8T.VckR9l.UofKPTtPvUx3ZfNSAQ.ruUsFBCvC1mz49quqhSrPjK4p25hfLcDZF/86iiA0n38Dh/", Hashing.sha512Crypt("hashcat", "$6$rounds=4000$52450745"));
    }

    @Test
    void customAlgorithm10() { assertEquals("bd17b9d14010a1d4f8c8077f1be1e20b9364d9979bbcf8591337e952cc6037026aa4a2025543d39169022344b4dd1d20f499395533e35705296034bbf7e7d663", Hashing.customAlgorithm10("chatbooks", "NqXCvAHUpAWAco3hVTG5Sg0FfmJRQPKi0LvcHwylzXHhSNuWwvYdMSSGzswi0ZdJ")); }

    @Test
    void sha256Crypt() {
        assertEquals("$5$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD", Hashing.sha256Crypt("hashcat", "$5$GX7BopJZJxPc/KEK"));
        assertEquals("$5$rounds=5000$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD", Hashing.sha256Crypt("hashcat", "$5$rounds=5000$GX7BopJZJxPc/KEK"));
        assertEquals("$5$rounds=4000$GX7BopJZJxPc/KEK$sn.Ds3.Gebi0n6vih/PyOUqlagz5FGk1ITvNh7f1ZMC", Hashing.sha256Crypt("hashcat", "$5$rounds=4000$GX7BopJZJxPc/KEK"));
    }

    @Test
    void authMeSHA256() { assertEquals("$SHA$7218532375810603$bfede293ecf6539211a7305ea218b9f3f608953130405cda9eaba6fb6250f824", Hashing.authMeSHA256("hashcat", "7218532375810603")); }

    @Test
    void hmacSHA1SaltAsKey() { assertEquals("d89c92b4400b15c39e462a8caa939ab40c3aeeea", Hashing.hmacSHA1SaltAsKey("hashcat", "1234")); }

}

