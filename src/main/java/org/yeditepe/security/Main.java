package org.yeditepe.security;

import org.apache.hadoop.hbase.util.Bytes;
import org.yeditepe.security.cipher.AesCtr;
import org.yeditepe.security.cipher.AesGcm;
import org.yeditepe.security.utils.CryptoUtils;
import org.yeditepe.security.utils.FileUtils;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;


import javax.crypto.SecretKey;
import java.util.Arrays;

import static org.yeditepe.security.cipher.AesGcm.*;

public class Main {

    public static void printArray(byte[] arr)
    {
        for (byte b : arr) System.out.print(b + " ");
        System.out.println();
    }

    public static void main(String[] args) throws Exception {

        System.out.println(System.getProperty("user.dir"));

        /*
        String OUTPUT_FORMAT = "%-30s:%s";

        String pText = "Hello World AES-GCM, Welcome to Cryptography!";

        // encrypt and decrypt need the same key.
        // get AES 256 bits (32 bytes) key
        SecretKey secretKey = CryptoUtils.getAESKey(AES_KEY_BIT);

        // encrypt and decrypt need the same IV.
        // AES-GCM needs IV 96-bit (12 bytes)
        byte[] iv = CryptoUtils.getRandomNonce(IV_LENGTH_BYTE);

        byte[] encryptedText = AesGcm.encryptWithPrefixIV(pText.getBytes(UTF_8), secretKey, iv);

        System.out.println("\n------ AES GCM Encryption ------");
        System.out.println(String.format(OUTPUT_FORMAT, "Input (plain text)", pText));
        System.out.println(String.format(OUTPUT_FORMAT, "Key (hex)", CryptoUtils.hex(secretKey.getEncoded())));
        System.out.println(String.format(OUTPUT_FORMAT, "IV  (hex)", CryptoUtils.hex(iv)));
        System.out.println(String.format(OUTPUT_FORMAT, "Encrypted (hex) ", CryptoUtils.hex(encryptedText)));
        System.out.println(String.format(OUTPUT_FORMAT, "Encrypted (hex) (block = 16)", CryptoUtils.hexWithBlockSize(encryptedText, 16)));

        System.out.println("\n------ AES GCM Decryption ------");
        System.out.println(String.format(OUTPUT_FORMAT, "Input (hex)", CryptoUtils.hex(encryptedText)));
        System.out.println(String.format(OUTPUT_FORMAT, "Input (hex) (block = 16)", CryptoUtils.hexWithBlockSize(encryptedText, 16)));
        System.out.println(String.format(OUTPUT_FORMAT, "Key (hex)", CryptoUtils.hex(secretKey.getEncoded())));

        String decryptedText = AesGcm.decryptWithPrefixIV(encryptedText, secretKey);
        System.out.println(String.format(OUTPUT_FORMAT, "Decrypted (plain text)", decryptedText));


        byte[] key = Bytes.toBytes("1234567890123456");
        try
        {
            AesCtr cip = new AesCtr(key);

            byte[] originalData = Bytes.toBytes("Do you think it's air that you breath?");

            System.out.println("Original Data: ");
            printArray(originalData);

            byte[] encData = cip.encrypt(originalData);

            System.out.println("Encrypted Data: ");
            printArray(encData);

            byte[] decData = cip.decrypt(encData);

            System.out.println("Decrypted Data: ");
            printArray(decData);

            if(! Arrays.equals(originalData, decData))
            {
                throw new Exception("AesCtr encryption decryption mechanism failed. Data changes after encryption and decryption!!");
            }
        }
        catch (Exception e)
        {
            throw new Exception("AesCtr encrypt test failed.");
        }

         */
    }

}
