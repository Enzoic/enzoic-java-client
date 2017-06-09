package com.passwordping.client.utilities;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Base64.*;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.jna.Size_t;
import de.mkammerer.argon2.jna.Uint32_t;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.mindrot.jbcrypt.BCrypt;
import de.mkammerer.argon2.jna.Argon2Library;
import com.sun.jna.Library;
import com.sun.jna.Native;
import org.apache.commons.codec.digest.Md5Crypt;

public class Hashing {

    public static String md5(final String toHash) {
        return bytesToHex(md5Binary(toHash));
    }

    public static byte[] md5Binary(final String toHash) {
        return Hashing.md5Binary(utf8ToByteArray(toHash));
    }

    public static byte[] md5Binary(final byte[] toHash) {
        try {
            return MessageDigest.getInstance("MD5").digest(toHash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing required hashing algorithm: MD5");
        }
    }

    public static String sha1(final String toHash) {
        try {
            return bytesToHex(MessageDigest.getInstance("SHA-1").digest(utf8ToByteArray(toHash)));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing required hashing algorithm: SHA-1");
        }

    }

    public static String sha256(final String toHash) {
        try {
            return bytesToHex(MessageDigest.getInstance("SHA-256").digest(utf8ToByteArray(toHash)));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing required hashing algorithm: SHA-256");
        }
    }

    public static String sha512(final String toHash) {
        return bytesToHex(sha512Binary(toHash));
    }

    public static byte[] sha512Binary(final String toHash) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(utf8ToByteArray(toHash));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing required hashing algorithm: SHA-512");
        }
    }

    public static String crc32(final String toHash) {
        java.util.zip.CRC32 crc32 = new java.util.zip.CRC32();
        crc32.update(utf8ToByteArray(toHash));

        return Long.toHexString(crc32.getValue()).toLowerCase();
    }

    public static String whirlpool(final String toHash) {
        return bytesToHex(whirlpoolBinary(toHash));
    }

    public static byte[] whirlpoolBinary(final String toHash) {
        java.security.Security.addProvider(new BouncyCastleProvider());

        try {
            return MessageDigest.getInstance("Whirlpool").digest(utf8ToByteArray(toHash));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing required hashing algorithm: Whirlpool");
        }
    }

    public static String myBB(final String toHash, final String salt) {
        return Hashing.md5(Hashing.md5(salt) + Hashing.md5(toHash));
    }

    public static String vBulletin(final String toHash, final String salt) {
        return Hashing.md5(Hashing.md5(toHash) + salt);
    }

    public static String bCrypt(final String toHash, final String salt) {
        boolean yVersion = salt.startsWith("$2y$");
        String checkedSalt = salt;

        if (yVersion) {
            checkedSalt = "$2a$" + salt.substring(4);
        }

        String result = BCrypt.hashpw(toHash, checkedSalt);

        if (yVersion) {
            return "$2y$" + result.substring(4);
        }
        else {
            return result;
        }
    }

    public static String phpbb3(final String toHash, final String salt) {

        if (!salt.substring(0, 3).equals("$H$")) {
            return "";
        }

        final String itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        byte[] toHashBytes = utf8ToByteArray(toHash);
        int count = (int)Math.pow(2, itoa64.indexOf(salt.charAt(3)));
        String justsalt = salt.substring(4, 12);

        byte[] hash = Hashing.md5Binary(justsalt + toHash);
        do {
            byte[] t = new byte[hash.length + toHashBytes.length];
            System.arraycopy(hash, 0, t, 0, hash.length);
            System.arraycopy(toHashBytes, 0, t, hash.length, toHashBytes.length);
            hash = Hashing.md5Binary(t);
        } while (--count > 0);

        String hashout = "";
        int i = 0;
        count = 16;
        int value;

        do {
            value = hash[i] + (hash[i] < 0 ? 256 : 0);
            ++i;
            hashout += itoa64.charAt(value & 63);
            if (i < count) {
                value |= (hash[i] + (hash[i] < 0 ? 256 : 0)) << 8;
            }
            hashout += itoa64.charAt((value >> 6) & 63);
            if (i++ >= count) {
                break;
            }
            if (i < count) {
                value |= (hash[i] + (hash[i] < 0 ? 256 : 0)) << 16;
            }
            hashout += itoa64.charAt((value >> 12) & 63);
            if (i++ >= count) {
                break;
            }
            hashout += itoa64.charAt((value >> 18) & 63);
        } while (i < count);

        return salt + hashout;
    }

    public static String customAlgorithm1(final String toHash, final String salt) {
        return bytesToHex(xor(Hashing.sha512Binary(toHash + salt), Hashing.whirlpoolBinary(salt + toHash)));
    }

    public static String customAlgorithm2(final String toHash, final String salt) {
        return Hashing.md5(toHash + salt);
    }

    public static String customAlgorithm4(final String toHash, final String salt) {
        return Hashing.bCrypt(Hashing.md5(toHash), salt);
    }

    public static String argon2(final String toHash, final String salt) {

        // defaults
        Uint32_t iterations = new Uint32_t(3);
        Uint32_t memoryCost = new Uint32_t(1024);
        Uint32_t parallelism = new Uint32_t(2);
        Uint32_t hashLength = new Uint32_t(20);
        Size_t hashLengthSize = new Size_t(20);
        Argon2Factory.Argon2Types argonType = Argon2Factory.Argon2Types.ARGON2d;
        String justSalt = salt;

        // check if salt has settings encoded in it
        if (salt.startsWith("$argon2")) {
            // apparently has settings encoded in it - use these
            if (salt.startsWith("$argon2i"))
                argonType = Argon2Factory.Argon2Types.ARGON2i;

            String[] saltComponents = salt.split("\\$");
            if (saltComponents.length == 5) {
                justSalt = new String(Base64.getDecoder().decode(saltComponents[4]));
                String[] saltParams = saltComponents[3].split("\\,");

                for (int i = 0; i < saltParams.length; i++) {
                    try {
                        String saltParam = saltParams[i];
                        String[] saltParamValues = saltParam.split("\\=");
                        switch (saltParamValues[0]) {
                            case "t":
                                iterations = new Uint32_t(Integer.parseInt(saltParamValues[1]));
                                break;
                            case "m":
                                memoryCost = new Uint32_t(Integer.parseInt(saltParamValues[1]));
                                break;
                            case "p":
                                parallelism = new Uint32_t(Integer.parseInt(saltParamValues[1]));
                                break;
                            case "l":
                                hashLength = new Uint32_t(Integer.parseInt(saltParamValues[1]));
                                hashLengthSize = new Size_t(Integer.parseInt(saltParamValues[1]));
                                break;
                        }
                    }
                    catch (NumberFormatException ex) {
                        // ignore invalid parameters
                    }
                }
            }
        }

        byte[] toHashBytes = utf8ToByteArray(toHash);
        byte[] saltBytes = utf8ToByteArray(justSalt);

        int len = Argon2Library.INSTANCE.argon2_encodedlen(iterations, memoryCost, parallelism,
                new Uint32_t(saltBytes.length), hashLength, argonType.ordinal).intValue();
        final byte[] outputHash = new byte[len];

        int result;
        if (argonType == Argon2Factory.Argon2Types.ARGON2i)
            result = Argon2Library.INSTANCE.argon2i_hash_encoded(
                    iterations, memoryCost, parallelism,
                    toHashBytes, new Size_t(toHashBytes.length),
                    saltBytes, new Size_t(saltBytes.length),
                    hashLengthSize, outputHash, new Size_t(outputHash.length));
        else
            result = Argon2Library.INSTANCE.argon2d_hash_encoded(
                    iterations, memoryCost, parallelism,
                    toHashBytes, new Size_t(toHashBytes.length),
                    saltBytes, new Size_t(saltBytes.length),
                    hashLengthSize, outputHash, new Size_t(outputHash.length));

        if (result != Argon2Library.ARGON2_OK) {
            String errMsg = Argon2Library.INSTANCE.argon2_error_message(result);
            throw new RuntimeException(String.format("Argon2 hash failure: %s (%d)", errMsg, result));
        }

        return Native.toString(outputHash);
    }

    public static String md5Crypt(final String toHash, final String salt) { return Md5Crypt.md5Crypt(utf8ToByteArray(toHash), salt); }

    private static byte[] xor(byte[] array1, byte[] array2) {
        byte[] result = new byte[array1.length];

        for (int i = 0; i < array1.length; i++) {
            result[i] = (byte)(array1[i] ^ array2[i]);
        }

        return result;
    }

    final protected static char[] hexArray = "0123456789abcdef".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    private static byte[] utf8ToByteArray(final String toConvert) {
        try {
            return toConvert.getBytes("UTF-8");
        }
        catch (UnsupportedEncodingException ex) {
            throw new RuntimeException("Missing required encoding: UTF-8");
        }
    }
}
