package com.passwordping.client;

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
