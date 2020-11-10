package org.yeditepe.security.utils;

import com.opencsv.CSVReader;
import com.opencsv.CSVWriter;
import org.apache.commons.io.FileUtils;

import java.io.*;
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


public class Utils {
    public static final String BOOK = "war-and-peace.txt";
    public static final String ENCRYPT = "encrypt";
    public static final String DECRYPT = "decrypt";
    public static final Path RESOURCE = Paths.get(Utils.class.getResource("/").getPath());
    public static final String DOT = ".";
    public static final String PROJECT_DIR = System.getProperty("user.dir");
    public static final String BASE_DIR = "/Users/fuatkarakus/dev/IdeaProjects";
    public static final String CSV = "result.csv";
    public static final String SEPERATOR = ">";
    public static final char SEPERATOR_CHAR = '>';

    public static File getBook() {
        return new File(Objects.requireNonNull(Utils.class.getClassLoader().getResource(BOOK)).getPath());
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

    public static List<String> getLineAsList(String str) {
        return Stream.of(str.split(SEPERATOR, -1))
                .collect(Collectors.toList());
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
        return Stream.of(data).map(i -> escapeSpecialCharacters(i)).collect(Collectors.joining(SEPERATOR));
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

    public static String toStr(byte[] arr)
    {
        StringBuilder sb = new StringBuilder();
        for(int a = 0; a<arr.length; a++)
            sb.append(arr[a] + " ");
        return sb.toString();
    }
    public static void writeDecrypted(byte[] bytes, Integer line) throws IOException {


        FileUtils.writeStringToFile(new File(line + ".txt"), toStr(bytes));

    }

    public static byte[] readDecrypted(Integer line) throws IOException {
        File decrypFile = new File(line + ".txt");
        String data = FileUtils.readFileToString(decrypFile, "UTF-8");
        List<Integer> intList =  Stream.of(data.split("\\s+"))
                .map(Integer::valueOf)
                .collect(Collectors.toList());

        int[] strings = intList.stream().mapToInt(i->i).toArray();

        byte[] arr = new byte[strings.length];

        for (int i = 0; i< strings.length; i++){
            arr[i] = (byte) strings[i];
        }

        return arr;

    }


    /**
     * Update CSV by row and column
     *
     * @param replace Replacement for your cell value
     * @param row Row for which need to update
     * @param col Column for which you need to update
     * @throws IOException
     */
    public static void updateCSV(String replace,
                                 int row, int col)  {

        // csv file
        File inputFile = new File(CSV);

        // Read existing file
        List<String[]> csvBody;
        try (CSVReader reader = new CSVReader(new FileReader(inputFile), SEPERATOR_CHAR)) {
            csvBody = reader.readAll();
            // get CSV row column  and replace with by using row and column
            csvBody.get(row)[col] = replace;
            reader.close();
            CSVWriter writer = new CSVWriter(new FileWriter(inputFile), SEPERATOR_CHAR);
            writer.writeAll(csvBody);
            writer.flush();
            writer.close();

        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
