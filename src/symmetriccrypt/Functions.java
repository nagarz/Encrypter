/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package symmetriccrypt;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author dani
 */
public class Functions {
    
    public static SecretKey secretKeyGen(Integer size, String password, String alg) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        SecretKey sKey = null;
        byte[] data = password.getBytes("UTF-8");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(data);
        byte[] hash = digest.digest();
        byte[] key = Arrays.copyOf(hash, size / 8);
        sKey = new SecretKeySpec(key, alg);
        return sKey;
    }

    public static byte[] encryptData(SecretKey secretKey, String data, String algorithm) {
        byte[] encryptedData = null;
        try {
            byte[] clearData = data.getBytes("UTF-8");
            Cipher cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            encryptedData = cipher.doFinal(clearData);
        } catch (Exception ex) {
            System.err.println("Error xifrant les dades: " + ex);
        }
        return encryptedData;
    }

    public static byte[] decryptData(SecretKey secretKey, String data, String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] clearData = null;
        byte[] encryptedData = null;
        encryptedData = hexStringToByteArray(data);
        Cipher cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        clearData = cipher.doFinal(encryptedData);
        return clearData;
    }

    public static String byteArrayToHexString(byte[] bytes) {
        char[] toDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        int l = bytes.length;
        char[] output = new char[l << 1];
        for (int i = 0, j = 0; i < l; i++) {
            output[j++] = toDigits[(0xF0 & bytes[i]) >>> 4];
            output[j++] = toDigits[0x0F & bytes[i]];
        }
        return new String(output);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

}
