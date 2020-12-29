package org.yeditepe.security;

import javax.crypto.Cipher;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.*;

public class PKClient
{
    public static final int kBufferSize = 8192;

    public static void somemain(String[] args) {
        try {
            // Generate new key
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            String message = "The quick brown fox jumps over the lazy dog.";

            // Compute signature
            Signature instance = Signature.getInstance("SHA1withRSA");
            instance.initSign(privateKey);
            instance.update((message).getBytes());
            byte[] signature = instance.sign();

            // Compute digest
            MessageDigest sha1 = MessageDigest.getInstance("SHA1");
            byte[] digest = sha1.digest((message).getBytes());

            // Encrypt digest
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            byte[] encryptedMsg = cipher.doFinal(digest);

            //Store the key in a file
            ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("KeyFile.xx"));
            out.writeObject(privateKey);
            out.close();

            System.out.println("Client - Message: " + message);
            System.out.println("Client - Encrypted: " + asHex(encryptedMsg));

            String host = "localhost";
            int port = 7999;
            Socket s = new Socket(host, port);

            //Open stream to cipher server
            DataOutputStream os = new DataOutputStream(s.getOutputStream());
            os.writeInt(encryptedMsg.length);
            os.write(encryptedMsg);
            os.writeInt(digest.length);
            os.write(digest);
            os.writeInt(signature.length);
            os.write(signature);

            os.flush();
            os.close();

            //Close socket
            s.close();

        }catch (Exception e) {
            e.printStackTrace();
        }
    }

    //Function to make the bytes printable (hex format)
    public static String asHex(byte buf[]) {
        StringBuilder strbuf = new StringBuilder(buf.length * 2);
        int i;
        for (i = 0; i < buf.length; i++) {
            if (((int) buf[i] & 0xff) < 0x10) {
                strbuf.append("0");
            }
            strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
        }
        return strbuf.toString();
    }
}