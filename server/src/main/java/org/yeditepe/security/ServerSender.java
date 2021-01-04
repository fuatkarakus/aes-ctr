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
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;


// Receiver should be client
// Client download file from server
public class ServerSender {
// dosya serverda bulunuyor
    private static final int PORT = 8080;

    public static void execute() throws Exception {

        System.out.println("The server is running.");

        Scanner ss = new Scanner(System.in);
        System.out.println("Do you want to un-send some parts ? y or n");

        boolean doNotSend = false;
        String s = ss.nextLine();
        if (s == "y") {
            doNotSend = true;
        } else if (s == "n") {
            doNotSend = false;
        }

        ServerSocket listener = new ServerSocket(PORT);

        try {
           while (true) {
                new Handler(listener.accept(), doNotSend).start();
           }

        } finally {
            listener.close();
        }
    }

    private static class Handler extends Thread {
        private Socket socket;
        private boolean doNotSend;
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

        private void sendString(byte[] aesKey, List<String> send, String name, String size) throws IOException, GeneralSecurityException {

            //  InputStream willSend = Utils.convertObjectToInputStream(send);
            // Encrypt the name of the file and its size using AES and send it over the socket
            String fileNameAndSize = name + "\n" + size + "\n" + Utils.getSizeOfByte(send) + "\n";

            ByteArrayInputStream fileInfoStream = new ByteArrayInputStream(fileNameAndSize.getBytes(StandardCharsets.UTF_8));

            SecretKeySpec aeskeySpec = new SecretKeySpec(aesKey, "AES");
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.ENCRYPT_MODE, aeskeySpec);
            CipherOutputStream cipherOutStream = new CipherOutputStream(out, aesCipher);

            ProtocolUtilities.sendBytes(fileInfoStream,cipherOutStream);
            System.out.println(send.get(52161));
            // send the the hashmap
            // send line by line
            for (String str : send) {
                str = str + "\n";
                ProtocolUtilities.sendBytes( new ByteArrayInputStream(str.getBytes(StandardCharsets.UTF_8)), cipherOutStream) ;
            }

            out.write(aesCipher.doFinal());
            //out.write("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n".getBytes(StandardCharsets.UTF_8));
            out.flush();
            // ArrayList<String> clientResponse = ProtocolUtilities.consumeAndBreakHeader(in);
            socket.close();

        }
        private void sendFile(byte[] aesKey, List<String> send, String name, String size) throws IOException, GeneralSecurityException {

            //  InputStream willSend = Utils.convertObjectToInputStream(send);
            // Encrypt the name of the file and its size using AES and send it over the socket
            List<File> fileList = Utils.getParts();
            SecretKeySpec aeskeySpec = new SecretKeySpec(aesKey, "AES");
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.ENCRYPT_MODE, aeskeySpec);
            CipherOutputStream cipherOutStream = new CipherOutputStream(out, aesCipher);

            String totalFile = fileList.size() + "\n";
            ByteArrayInputStream strasdl = new ByteArrayInputStream(totalFile.getBytes(StandardCharsets.UTF_8));
            // önce kaç tane dosya göndereceğimizi gönder
            ProtocolUtilities.sendBytes(strasdl,cipherOutStream);

            for (File file : fileList) {

                String fileNameAndSize = file.getName() + "\n" + file.length() + "\n";
                ByteArrayInputStream fileInfoStream = new ByteArrayInputStream(fileNameAndSize.getBytes(StandardCharsets.UTF_8));
                // Dosya bilgilerini gönderiyoruz.
                ProtocolUtilities.sendBytes(fileInfoStream,cipherOutStream);

                FileInputStream fileStream = new FileInputStream(file);
                ProtocolUtilities.sendBytes(fileStream,cipherOutStream);
            }

            out.write(aesCipher.doFinal());
            out.write("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n".getBytes(StandardCharsets.UTF_8));
            out.flush();
            // ArrayList<String> clientResponse = ProtocolUtilities.consumeAndBreakHeader(in);
            socket.close();

        }

        private void sendRequestedFiles(byte[] aesKey, String missing) throws IOException, GeneralSecurityException {

            List<File> fileList = Utils.getParts();

            SecretKeySpec aeskeySpec = new SecretKeySpec(aesKey, "AES");
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.ENCRYPT_MODE, aeskeySpec);

            CipherOutputStream cipherOutStream = new CipherOutputStream(out, aesCipher);

            List<String> items= Stream.of(missing.split(","))
                    .map(String::trim)
                    .collect(Collectors.toList());

            for (File file : fileList) {
                if (items.stream().anyMatch(i -> file.getName().contains(i))) {
                    String fileNameAndSize = file.getName() + "\n" + file.length() + "\n";
                    ByteArrayInputStream fileInfoStream = new ByteArrayInputStream(fileNameAndSize.getBytes(StandardCharsets.UTF_8));
                    // Dosya bilgilerini gönderiyoruz.
                    ProtocolUtilities.sendBytes(fileInfoStream,cipherOutStream);

                    FileInputStream fileStream = new FileInputStream(file);
                    ProtocolUtilities.sendBytes(fileStream,cipherOutStream);
                }
            }

            out.write(aesCipher.doFinal());
            out.write("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n".getBytes(StandardCharsets.UTF_8));
            out.flush();
            // ArrayList<String> clientResponse = ProtocolUtilities.consumeAndBreakHeader(in);
            socket.close();

        }

        public Handler(Socket socket, boolean doNotSend) {
            this.socket = socket;
            this.doNotSend = doNotSend;
        }

        @SneakyThrows
        public void run() {
            String command;
            String second = null;
            try {
                in = new BufferedInputStream(socket.getInputStream());
                out = new BufferedOutputStream(socket.getOutputStream());
                ArrayList<String> headerParts = ProtocolUtilities.consumeAndBreakHeader(in);
                command = headerParts.get(0);
                if (headerParts.size() > 1) {
                    second = headerParts.get(1);
                }
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
                    System.out.println("Client request for specific files.....");
                    try {
                        // ilk önce aes key okuyor.
                        byte[] aesKey2 = readAndDecryptAesKey(privateRsaKey);

                        System.out.println("Session KEY received...");
                        System.out.println(Arrays.toString(aesKey2));

                        System.out.println("Starting to file transfer...");

                        sendRequestedFiles( aesKey2 , second);

                        System.out.println("Requested specific file sent...");

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
                default:
                    sendErrorMessage("INVALID COMMAND");
                    System.out.println("Invalid command detected: " + command);
            }
        }
    }
}