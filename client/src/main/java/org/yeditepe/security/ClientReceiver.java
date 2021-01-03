package org.yeditepe.security;

import org.apache.commons.io.IOUtils;
import org.apache.hadoop.hbase.util.Bytes;
import org.yeditepe.security.utils.Command;
import org.yeditepe.security.utils.ProtocolUtilities;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class ClientReceiver {

    private static final String hostName = "localhost";
    private static final int portNumber = 8080;

    private static void sendEncryptedAesKEY(OutputStream out, byte[] publicKey,byte[] aesKey)
            throws GeneralSecurityException, IOException {

        // send header and encrypted AES. AES is encrypted using private RSA key.
        // out.write(Command.SESSION_KEY_TRANSFER_HEADER.getBytes(StandardCharsets.US_ASCII));

        Cipher pkCipher = Cipher.getInstance("RSA");
        PublicKey pk = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKey));
        pkCipher.init(Cipher.ENCRYPT_MODE, pk);

        ByteArrayOutputStream tempByteStream = new ByteArrayOutputStream();
        CipherOutputStream cipherStream = new CipherOutputStream(tempByteStream, pkCipher);
        cipherStream.write(aesKey);
        cipherStream.close();
        System.out.println("Session key sent..." );
        System.out.println(Arrays.toString(aesKey));
        tempByteStream.writeTo(out);
    }

    private static byte[] getPublicKey() throws IOException {
        Socket socket = new Socket(hostName, portNumber);

        BufferedOutputStream out = new BufferedOutputStream(socket.getOutputStream()); // giden
        BufferedInputStream in = new BufferedInputStream(socket.getInputStream()); // gelen

        out.write( Command.SEND_PUBLIC_KEY_HEADER.getBytes(StandardCharsets.UTF_8));
        out.flush();

        ArrayList<String> headerParts = ProtocolUtilities.consumeAndBreakHeader(in);
        if (!headerParts.get(0).equals("PUBLIC KEY")) {
            System.err.println("Failed to obtain public key. The Server responded with the following:");
            for (String msg : headerParts)
                System.err.println(msg);
            System.exit(1);
        }
        int keySize = Integer.parseInt(headerParts.get(1));
        byte[] publicKey = new byte[keySize];
        in.read(publicKey);
        return publicKey;
    }

    private static byte[] generateAesKey() throws NoSuchAlgorithmException {
        byte[] secretAesKey = null;
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(ProtocolUtilities.KEY_SIZE_AES); // AES key length 128 bits (16 bytes)
        secretAesKey = kgen.generateKey().getEncoded();
        return secretAesKey;
    }

    private static byte[] generateIV() {
        return Bytes.toBytes("asdfghjklzxcvbnm"); // 16 byte
    }

    private static String scanLineFromCipherStream(CipherInputStream cstream) throws IOException {
        StringBuilder line = new StringBuilder();
        char c;
        while ((c = (char) cstream.read()) != '\n') {
            line.append(c);
        }
        return line.toString();
    }

    private static List<String> scanLineFromObjectStream(ObjectInputStream cstream, String lineNumber) throws IOException {

        List<String> list = new ArrayList<>();
        int max = Integer.parseInt(lineNumber);

        StringBuilder line = new StringBuilder(100_000);
        char c;
        for (int i = 0; i < max; i++) {
            while ((c = (char) cstream.read()) != '\n') {
                line.append(c);
            }
            list.add(line.toString());
        }

        return list;
    }

    private static String receiveInformation(byte[] aesKey) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IOException {

        Socket socket = new Socket(hostName, portNumber);

        BufferedOutputStream out = new BufferedOutputStream(socket.getOutputStream()); // giden
        BufferedInputStream in = new BufferedInputStream(socket.getInputStream()); // gelen

        out.write( Command.SEND_SIZE_HEADER.getBytes(StandardCharsets.UTF_8));
        out.flush();

        Cipher aesCipher = Cipher.getInstance("AES");
        SecretKeySpec aeskeySpec = new SecretKeySpec(aesKey, "AES");
        aesCipher.init(Cipher.DECRYPT_MODE, aeskeySpec);
        CipherInputStream cipherInputStream = new CipherInputStream(in, aesCipher);
        String fileName = scanLineFromCipherStream(cipherInputStream);
        String fileSize = scanLineFromCipherStream(cipherInputStream);
        return fileSize;
    }

    private static boolean receiveFile(byte[] aesKey, byte[] publicKey) throws GeneralSecurityException, IOException, ClassNotFoundException {

        Socket socket = new Socket(hostName, portNumber);

        BufferedOutputStream out = new BufferedOutputStream(socket.getOutputStream()); // giden
        BufferedInputStream in = new BufferedInputStream(socket.getInputStream()); // gelen

        out.write( Command.SEND_FILE_HEADER.getBytes(StandardCharsets.UTF_8));
        sendEncryptedAesKEY(out,publicKey,aesKey);
        out.flush();

        Cipher aesCipher = Cipher.getInstance("AES");
        SecretKeySpec aeskeySpec = new SecretKeySpec(aesKey, "AES");
        aesCipher.init(Cipher.DECRYPT_MODE, aeskeySpec);

        CipherInputStream cipherInputStream = new CipherInputStream(in, aesCipher);
        String fileName = scanLineFromCipherStream(cipherInputStream);
        System.out.println("Incoming file : "+ fileName);

        String lineNumber = scanLineFromCipherStream(cipherInputStream);
        System.out.println("Incoming line number : "+ lineNumber);
        String byteSize = scanLineFromCipherStream(cipherInputStream);
        System.out.println("Incoming byte size : "+ byteSize);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        ProtocolUtilities.sendBytes(cipherInputStream, baos, Long.parseLong(byteSize));
        baos.flush();
        baos.close();

        ByteArrayInputStream byteArrayInputStream =  new ByteArrayInputStream(baos.toByteArray());
        String result = IOUtils.toString(byteArrayInputStream, StandardCharsets.UTF_8);

        System.out.println("Received line : " +result);

        return true ;
    }

    public static void execute() throws IOException {

        System.out.println("Using host name: "+hostName + " and port number: " + portNumber + "...");

        byte[] publicRsaKey, secretAesKey, iv;

        try {
            publicRsaKey = getPublicKey(); // burada socket açıyor
            System.out.println("Public Key Received");

            secretAesKey = generateAesKey();
            // iv = generateIV();

            boolean isSuccessful = receiveFile(secretAesKey, publicRsaKey); // burada socket açıyor

            if (isSuccessful){

                // TODO detect which part of file does not receive successfully

               // System.out.println("File was successfully sent.");
            } else {
               // System.out.println("File was not sent.");
            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
            System.err.println("File not found.");
        } catch (IOException e) {
            e.printStackTrace();
            System.err.println("There was an error connecting to the server.");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.err.println("Failed to generate AES key.");
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            System.err.println("Unknown security error.");
        } catch (ClassNotFoundException e) {
            System.err.println("ClassNotFoundException  error.");
            e.printStackTrace();
        }
    }
}