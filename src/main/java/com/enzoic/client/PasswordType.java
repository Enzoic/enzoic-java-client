package com.enzoic.client;

import com.google.gson.annotations.SerializedName;

/**
 * Specifies a hash algorithm type for a password
 */
enum PasswordType {
    @SerializedName("0")
    Plaintext (0),

    @SerializedName("1")
    MD5 (1),

    @SerializedName("2")
    SHA1 (2),

    @SerializedName("3")
    SHA256 (3),

    @SerializedName("4")
    TripleDES (4),

    @SerializedName("5")
    IPBoard_MyBB (5),

    @SerializedName("6")
    vBulletinPre3_8_5 (6),

    @SerializedName("7")
    vBulletinPost3_8_5 (7),

    @SerializedName("8")
    BCrypt (8),

    @SerializedName("9")
    CRC32 (9),

    @SerializedName("10")
    PHPBB3 (10),

    @SerializedName("11")
    CustomAlgorithm1 (11),

    @SerializedName("12")
    SCrypt (12),

    @SerializedName("13")
    CustomAlgorithm2 (13),

    @SerializedName("14")
    SHA512 (14),

    @SerializedName("16")
    MD5Crypt (16),

    @SerializedName("17")
    CustomAlgorithm4 (17),

    @SerializedName("18")
    CustomAlgorithm5 (18),

    @SerializedName("19")
    osCommerce_AEF (19),

    @SerializedName("20")
    DESCrypt (20),

    @SerializedName("21")
    MySQLPre4_1 (21),

    @SerializedName("22")
    MySQLPost4_1 (22),

    @SerializedName("23")
    PeopleSoft (23),

    @SerializedName("24")
    PunBB (24),

    @SerializedName("25")
    CustomAlgorithm6 (25),

    @SerializedName("26")
    PartialMD5_20 (26),

    @SerializedName("27")
    AVE_DataLife_Diferior (27),

    @SerializedName("28")
    DjangoMD5 (28),

    @SerializedName("29")
    DjangoSHA1 (29),

    @SerializedName("30")
    PartialMD5_29 (30),

    @SerializedName("31")
    PliggCMS (31),

    @SerializedName("32")
    RunCMS_SMF1_1 (32),

    @SerializedName("33")
    NTLM (33),

    @SerializedName("34")
    SHA1Dash (34),

    @SerializedName("35")
    SHA384 (35),

    @SerializedName("36")
    CustomAlgorithm7 (36),

    @SerializedName("37")
    CustomAlgorithm8 (37),

    @SerializedName("38")
    CustomAlgorithm9 (38),

    @SerializedName("39")
    SHA512Crypt (39),

    @SerializedName("40")
    CustomAlgorithm10 (40),

    @SerializedName("41")
    SHA256Crypt(41),

    @SerializedName("42")
    AuthMeSHA256(42),

    @SerializedName("97")
    Unknown (97),

    @SerializedName("98")
    UnusablePassword (98),

    @SerializedName("99")
    None (99);

    private int numVal;

    PasswordType(int numVal) {
        this.numVal = numVal;
    }

    public int getNumVal() {
        return numVal;
    }
}
