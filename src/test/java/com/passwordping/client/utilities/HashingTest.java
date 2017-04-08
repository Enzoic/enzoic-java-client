package com.passwordping.client.utilities;

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
    }

    @Test
    void crc32() {
        assertEquals("972d361", Hashing.crc32("123456"));
    }
}

