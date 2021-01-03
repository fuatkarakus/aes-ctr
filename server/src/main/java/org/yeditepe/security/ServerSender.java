package org.yeditepe.security;

import lombok.SneakyThrows;
import org.yeditepe.security.utils.Command;
import org.yeditepe.security.utils.ProtocolUtilities;
import org.yeditepe.security.utils.Utils;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;


// Receiver should be client
// Client download file from server
public class ServerSender {
// dosya serverda bulunuyor
    private static final int PORT = 8080;

    public static void execute() throws Exception {

        System.out.println("The server is running.");

        ServerSocket listener = new ServerSocket(PORT);

        try {
           while (true) {
                new Handler(listener.accept()).start();
           }

        } finally {
            listener.close();
        }
    }

    private static class Handler extends Thread {
        private Socket socket;
        private InputStream in;
        private OutputStream out;
        public byte[] aesKey;

        private void sendPublicKey() throws IOException {
            StringBuilder messageHeader = new StringBuilder();
            messageHeader.append("PUBLIC KEY\n");

            File publicKeyFile = new File(Objects.requireNonNull(getClass().getClassLoader().getResource("public.der")).getPath());
            messageHeader.append(publicKeyFile.length() + "\n\n");
            System.out.println(Arrays.toString(Files.readAllBytes(publicKeyFile.toPath())));
            out.write(messageHeader.toString().getBytes(StandardCharsets.UTF_8));
            out.write(Files.readAllBytes(publicKeyFile.toPath()));
            out.flush();
        }

        private void sendErrorMessage(String msg) {
            try {
                msg = "ERROR\n" + msg + "\n\n";
                out.write(msg.getBytes(StandardCharsets.UTF_8));
            } catch (IOException e) {
                System.out.println("Failed to send an error message to client.");
                System.exit(1);
            }
        }

        private byte[] readAndDecryptAesKey(byte[] privateKeyFile) throws GeneralSecurityException, IOException {
            // read the encrypted AES key from the socket
            byte[] encryptedAesKey = new byte[ProtocolUtilities.KEY_SIZE_AES * 2];
            in.read(encryptedAesKey);
            // put the private RSA key in the appropriate data structure
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyFile);
            PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec);
            // Decipher the AES key using the private RSA key
            Cipher pkCipher = Cipher.getInstance("RSA");
            pkCipher.init(Cipher.DECRYPT_MODE, privateKey);
            CipherInputStream cipherInputStream = new CipherInputStream(new ByteArrayInputStream(encryptedAesKey), pkCipher);
            byte[] aesKey = new byte[ProtocolUtilities.KEY_SIZE_AES / 8];
            cipherInputStream.read(aesKey);
            cipherInputStream.close();
            return aesKey;
        }

        private String scanLineFromCipherStream(CipherInputStream cstream) throws IOException {
            StringBuilder line = new StringBuilder();
            char c;
            while ((c = (char) cstream.read()) != '\n') {
                line.append(c);
            }
            return line.toString();
        }

        private void sendFile(byte[] aesKey, List<String> send, String name, String size) throws IOException, GeneralSecurityException {

            //  InputStream willSend = Utils.convertObjectToInputStream(send);
            // Encrypt the name of the file and its size using AES and send it over the socket
            String fileNameAndSize = name + "\n" + size + "\n" + Utils.getSizeOfByte(send) + "\n";

            ByteArrayInputStream fileInfoStream = new ByteArrayInputStream(fileNameAndSize.getBytes(StandardCharsets.UTF_8));

            SecretKeySpec aeskeySpec = new SecretKeySpec(aesKey, "AES");
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.ENCRYPT_MODE, aeskeySpec);
            CipherOutputStream cipherOutStream = new CipherOutputStream(out, aesCipher);

            ProtocolUtilities.sendBytes(fileInfoStream,cipherOutStream);

            // send the the hashmap
            // send line by line
            for (String str : send) {
                str = str + "\n";
                ProtocolUtilities.sendBytes( new ByteArrayInputStream(str.getBytes(StandardCharsets.UTF_8)), cipherOutStream) ;
            }

            out.write(aesCipher.doFinal());
            out.write("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n".getBytes(StandardCharsets.UTF_8));
            out.flush();
            // ArrayList<String> clientResponse = ProtocolUtilities.consumeAndBreakHeader(in);
            socket.close();

        }

        public Handler(Socket socket) {
            this.socket = socket;
        }

        @SneakyThrows
        public void run() {
            String command;
            try {
                in = new BufferedInputStream(socket.getInputStream());
                out = new BufferedOutputStream(socket.getOutputStream());
                ArrayList<String> headerParts = ProtocolUtilities.consumeAndBreakHeader(in);
                command = headerParts.get(0);
                System.out.println(command);
            } catch (IOException e) {
                e.printStackTrace();
                System.err.println("Connection to client dropped.");
                return;
            } catch (NullPointerException e) {
                System.err.println("Unable to read command from client");
                return;
            }

            byte[] privateRsaKey = Files.readAllBytes(new File(Objects.requireNonNull(getClass().getClassLoader().getResource("private.der")).getPath()).toPath());

            switch (command) {
                case Command.SEND_PUBLIC_KEY:
                    try {
                        sendPublicKey();
                        System.out.println("Sent public key!...");
                    } catch (IOException e) {
                        e.printStackTrace();
                        System.err.println("Connection to client dropped. Failed to send public key.");
                    }
                    break;
                case Command.SEND_FILE:
                    System.out.println("Client want to file...");

                    try {
                        // ilk önce aes key okuyor.
                        byte[] aesKey = readAndDecryptAesKey(privateRsaKey);
                        System.out.println("Session KEY received...");
                        System.out.println(Arrays.toString(aesKey));

                        List<String> file = Utils.convertFileToList();

                        String size = String.valueOf(file.size());

                        String name = Utils.getFileName();

                        System.out.println("Starting to file transfer...");
                        // sonra dosyayı gönderiyor

                        System.out.println("Byte Size " + Utils.getSizeOfByte(file));
                        sendFile( aesKey, file, name, size );

                        // System.out.println("Is successfully sent : "  + isSuccessful);
                        System.out.println("Name: " + name);
                        System.out.println("Size:" + size);
                        System.out.println("byte size "+ file.get(0));
                        System.out.println("File sent...");

                    } catch (GeneralSecurityException e) {
                        e.printStackTrace();
                        sendErrorMessage("Failed to decrypt AES key and/or file content.");
                        System.err.println("Server failed to decrypt AES key and/or file content.");
                        return;
                    } catch (IOException e) {
                        e.printStackTrace();
                        System.err.println("Connection to client dropped.");
                        return;
                    }
                    break;
                case Command.SEND_PARTS:
                    // TODO

                    break;
                default:
                    sendErrorMessage("INVALID COMMAND");
                    System.out.println("Invalid command detected: " + command);
            }
        }
    }
}