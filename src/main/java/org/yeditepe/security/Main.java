package org.yeditepe.security;

import org.apache.hadoop.hbase.util.Bytes;
import org.yeditepe.security.cipher.AesCtr;

import java.util.Arrays;

public class Main {


    public static void printArray(byte[] arr)
    {
        for (byte b : arr) System.out.print(b + " ");
        System.out.println();
    }

    public static void main(String[] args) throws Exception {
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

    }

}
