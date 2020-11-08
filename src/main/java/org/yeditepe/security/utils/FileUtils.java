package org.yeditepe.security.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Objects;

import static org.yeditepe.security.cipher.AesGcm.UTF_8;

public class FileUtils {

    public static final String BOOK = "war-and-peace.txt";
    public static final String ENCRYPT = "encrypt";
    public static final String DECRYPT = "decrypt";
    public static final Path RESOURCE = Paths.get(FileUtils.class.getResource("/").getPath());
    public static final String DOT = ".";
    public static final String PROJECT_DIR = System.getProperty("user.dir");
    public static final String BASE_DIR = "/Users/fuatkarakus/dev/IdeaProjects";

    public static File getBook() {
        return  new File (Objects.requireNonNull(FileUtils.class.getClassLoader()
                        .getResource(BOOK)).getPath());
    }

    public static void writeToFile(String filePath, String data) throws IOException {
        Path path;
        if (Files.exists(Paths.get(filePath))) {
            path = Paths.get(filePath);
        } else {
            path = Files.createFile(Paths.get(filePath));
        }
        byte[] strToBytes = data.getBytes();
        Files.write(path, strToBytes);
    }

    public static String readFromFile(String filePath) throws IOException {
        Path path = Paths.get(filePath);
        return Files.readAllLines(path).get(0);
    }

    public static void createFiles(){
        File book = getBook();

        byte[] block = new byte[16];

        try (FileInputStream fis = new FileInputStream(book)) {

            int name = 2;
            while ((fis.read(block)) != -1) {

                String strBlock = new String(block, UTF_8);

                writeToFile(encryptFile(name), strBlock);
                Files.createFile(Paths.get(decryptFile(name)));
                name = name + 1;

            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // ready to encrypt
    public static String encryptFile(int name) {
        return BASE_DIR + File.separator + ENCRYPT + File.separator + name + DOT +ENCRYPT;
    }

    // ready to encrypt
    public static String decryptFile(int name) {
        return BASE_DIR + File.separator + DECRYPT + File.separator + name + DOT +DECRYPT;
    }

}
