package org.yeditepe.security.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.yeditepe.security.cipher.AesGcm.UTF_8;

public class FileUtils {

    public static final String BOOK = "war-and-peace.txt";
    public static final String ENCRYPT = "encrypt";
    public static final String DECRYPT = "decrypt";
    public static final Path RESOURCE = Paths.get(FileUtils.class.getResource("/").getPath());
    public static final String DOT = ".";
    public static final String PROJECT_DIR = System.getProperty("user.dir");
    public static final String BASE_DIR = "/Users/fuatkarakus/dev/IdeaProjects";
    public static final String CSV = "result.csv";

    public static File getBook() {
        return new File(Objects.requireNonNull(FileUtils.class.getClassLoader().getResource(BOOK)).getPath());
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

    public static void createFiles() {
        File book = getBook();

        byte[] block = new byte[16];
        List<String[]> dataLines = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(book);
             PrintWriter pw = new PrintWriter(new File(CSV))) {

            int name = 1;
            while ((fis.read(block)) != -1) {
                List<String> csvLine = new ArrayList<>();
                String strBlock = new String(block, UTF_8);
                // csvLine.add(String.valueOf(name));
                csvLine.add(strBlock);
                name = name + 1;
                String[] strings = csvLine.stream().toArray(String[]::new);
                dataLines.add(strings);
            }

            dataLines.stream().map(i -> convertToCSV(i)).forEach(pw::println);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String getSpesificLine(int num) throws IOException {
        String line = "" ;
        try (Stream<String> lines = Files.lines(Paths.get(CSV))) {
            line = lines.skip(num).findFirst().get();
        }
        return line;
    }

    public static String getSize(){
        String size = "";
        try (Stream<String> lines = Files.lines(Paths.get(CSV), Charset.defaultCharset())) {
            long numOfLines = lines.count();
            size = String.valueOf(numOfLines);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return size;
    }

    public static String convertToCSV(String[] data) {
        return Stream.of(data).map(i -> escapeSpecialCharacters(i)).collect(Collectors.joining(","));
    }

    public static String escapeSpecialCharacters(String data) {
        String escapedData = data.replaceAll("\\R", " ");
        if (data.contains(",") || data.contains("\"") || data.contains("'")) {
            data = data.replace("\"", "\"\"");
            escapedData = "\"" + data + "\"";
        }
        return escapedData;
    }

    // ready to encrypt
    public static String encryptFile(int name) {
        return BASE_DIR + File.separator + ENCRYPT + File.separator + name + DOT + ENCRYPT;
    }

    // ready to encrypt
    public static String decryptFile(int name) {
        return BASE_DIR + File.separator + DECRYPT + File.separator + name + DOT + DECRYPT;
    }

}
