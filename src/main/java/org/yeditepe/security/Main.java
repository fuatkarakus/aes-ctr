package org.yeditepe.security;

import org.apache.hadoop.hbase.util.Bytes;
import org.yeditepe.security.cipher.AesCtr;
import org.yeditepe.security.utils.FileUtils;

import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

import static org.yeditepe.security.cipher.AesGcm.UTF_8;

public class Main {

    public static void main(String[] args) throws Exception {

        // 16 bits secret key
        byte[] key = Bytes.toBytes("1234567890123456");
        byte[] iv  = Bytes.toBytes("asdfghjklzxcvbnm"); // should be random


        Scanner sc = new Scanner(System.in);
        System.out.println("Welcome to Cryptography! \n");
        System.out.println("Hello World AES-CTR ");
        System.out.println("Please select mode between encrypt(1) and decrypt(2)");
        while (!sc.hasNextInt())
            sc.next();
        int num1 = sc.nextInt();

        System.out.println("Pick a number between 1 - " + FileUtils.getSize());

        while (!sc.hasNextInt())
            sc.next();
        int num2 = sc.nextInt();
        String selected = FileUtils.getSpesificLine(num2);
        System.out.println("Selected Line : "+ selected);

        try {
            AesCtr cip = new AesCtr(key);

            if (num1 == 1) { // encrypt
                byte[] originalData = Bytes.toBytes(selected);
                System.out.println("Original Data: ");
                System.out.println(new String(originalData, UTF_8));
                byte[] encData = cip.encrypt(originalData, iv);
                System.out.println("Encrypted Data: ");
                // printArray(encData);
                System.out.println(new String(encData, UTF_8));
            } else { // decrypt

                List<String> line = FileUtils.getLineAsList(selected);
                // selected line ikiye bolmemiz lazim
                // ikinci kolonu decript edip
                // ilk kolon ile karsilastirmamiz lazim

                if( line.size() == 2 ) {
                    byte[] decData = cip.decrypt(Bytes.toBytes(line.get(1)));
                    byte[] bytesStr  = Bytes.toBytes(line.get(0));

                    System.out.println("Decrypted Data: ");
                    System.out.println(new String(decData));
                    if (!Arrays.equals(bytesStr, decData)) {
                        throw new Exception(
                                "AesCtr encryption decryption mechanism failed. Data changes after encryption and decryption!!");
                    }
                } else {

                    System.out.println("There is not a decrypted data ");
                    return;
                }
            }
        } catch (Exception e) {
            throw new Exception("AesCtr encrypt test failed.");
        }
    }

}
