package org.yeditepe.security;

import org.apache.hadoop.hbase.util.Bytes;
import org.yeditepe.security.cipher.AesCtr;
import org.yeditepe.security.utils.Utils;

import java.io.IOException;
import java.util.Arrays;
import java.util.Scanner;

import static org.yeditepe.security.cipher.AesGcm.UTF_8;

public class Server {

    public static void printArray(byte[] arr)
    {
        for(int a = 0; a<arr.length; a++)
            System.out.print(arr[a] + " ");
        System.out.println();
    }
    public static void main(String[] args) throws Exception {


        //System.out.println(Utils.getParts());

        ServerSender.execute();

        /*
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

        System.out.println("Pick a number between 1 - " + Utils.getSize());

        while (!sc.hasNextInt())
            sc.next();
        int num2 = sc.nextInt();
        String selected = Utils.getSpesificLine(num2);
        System.out.println("Selected Line : "+ selected);

            AesCtr cip = new AesCtr(key);

            if (num1 == 1) { // encrypt

                byte[] originalData = Bytes.toBytes(selected);
                System.out.println("Original Data: ");
                String orjinal = new String(originalData, UTF_8);

                System.out.println(orjinal);

                byte[] encData = cip.encrypt(originalData, iv);
                System.out.println("Encrypted Data: ");
                // printArray(encData);
                String encypt = new String(encData, UTF_8);
                System.out.println(encypt);

                byte[] decData = cip.decrypt(encData);

                System.out.println("Decrypted Data: ");
                System.out.println(new String(decData, UTF_8));

                Utils.writeDecrypted(encData, num2);

            } else { // decrypt

                try {

                    System.out.println("dosyadan okudugu data : ");
                    System.out.println(new String(Utils.readDecrypted(num2)));
                    byte[] decData = cip.decrypt((Utils.readDecrypted(num2)));
                    byte[] bytesStr  = Bytes.toBytes(selected);

                    System.out.println("Decrypted Data: ");
                    System.out.println(new String(decData));
                    if (!Arrays.equals(bytesStr, decData)) {
                        throw new Exception(
                                "AesCtr encryption decryption mechanism failed. Data changes after encryption and decryption!!");
                    }
                } catch (IOException e) {
                    System.out.println("There is not a decrypted data ");
                    return;
                }
            }

         */

    }

}
