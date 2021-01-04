package org.yeditepe.security.utils;

public class Command {

    public static final String SEND_PUBLIC_KEY = "SEND PUBLIC KEY";
    public static final String SEND_FILE = "SEND FILE";
    public static final String SEND_PARTS = "SEND PARTS";
    public static final String SEND_SIZE = "SEND SIZE";

    public static final String SESSION_KEY_TRANSFER = "SESSION KEY TRANSFER";
    public static final String FILE_TRANSFER = "FILE TRANSFER";

    public static final String DELIMITER = "\n\n";

    public static final String FILE_TRANSFER_HEADER = FILE_TRANSFER + DELIMITER;
    public static final String SEND_PUBLIC_KEY_HEADER = SEND_PUBLIC_KEY + DELIMITER;
    public static final String SESSION_KEY_TRANSFER_HEADER = SESSION_KEY_TRANSFER + DELIMITER;
    public static final String  SEND_SIZE_HEADER = SEND_SIZE + DELIMITER;
    public static final String  SEND_FILE_HEADER = SEND_FILE + DELIMITER;
    public static final String  SEND_PARTS_HEADER = SEND_PARTS + DELIMITER;

}
