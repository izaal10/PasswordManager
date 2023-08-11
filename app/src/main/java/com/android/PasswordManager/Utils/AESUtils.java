package com.android.PasswordManager.Utils;

import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESUtils {

    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String HEX = "0123456789ABCDEF";

    public static String encrypt(String cleartext, String keyValue)
            throws Exception {
        byte[] rawKey = getRawKey(keyValue);
        byte[] iv = generateRandomIV();
        byte[] result = encrypt(rawKey, iv, cleartext.getBytes());
        return toHex(iv) + toHex(result);
    }

    public static String decrypt(String encrypted, String keyValue)
            throws Exception {
        byte[] iv = toByte(encrypted.substring(0, 32));
        byte[] enc = toByte(encrypted.substring(32));
        byte[] rawKey = getRawKey(keyValue);
        byte[] result = decrypt(rawKey, iv, enc);
        return new String(result);
    }

    private static byte[] getRawKey(String keyValueString) throws Exception {
        byte[] keyValue = keyValueString.getBytes(StandardCharsets.UTF_8);
        SecretKey key = new SecretKeySpec(keyValue, "AES");
        return key.getEncoded();
    }

    private static byte[] encrypt(byte[] raw, byte[] iv, byte[] clear) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(iv));
        return cipher.doFinal(clear);
    }

    private static byte[] decrypt(byte[] raw, byte[] iv, byte[] encrypted) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(iv));
        return cipher.doFinal(encrypted);
    }

    private static byte[] generateRandomIV() {
        byte[] iv = new byte[16];
        // TODO: Generate a random IV here using a secure random generator
        return iv;
    }

    public static byte[] toByte(String hexString) {
        int len = hexString.length() / 2;
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++) {
            result[i] = (byte) Integer.parseInt(hexString.substring(2 * i, 2 * i + 2), 16);
        }
        return result;
    }

    public static String toHex(byte[] buf) {
        StringBuilder result = new StringBuilder(2 * buf.length);
        for (byte b : buf) {
            result.append(HEX.charAt((b >> 4) & 0x0f)).append(HEX.charAt(b & 0x0f));
        }
        return result.toString();
    }
}