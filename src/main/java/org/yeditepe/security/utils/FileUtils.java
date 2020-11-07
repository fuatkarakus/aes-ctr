package org.yeditepe.security.utils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Objects;

public class FileUtils {

    public static final String BOOK = "war-and-peace.txt";

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
}
