import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HexFormat;

public class CipherForge {
    private static final int KEY_SIZE = 256;
    private static final int SALT_SIZE = 16;
    private static final int NONCE_SIZE = 12;
    private static final int TAG_SIZE = 128; // 128-bit authentication tag
    private static final int PASSWORD_LENGTH = 32;
    private static final int PBKDF2_ITERATIONS = 1000000;
    private static final String CHARACTER_POOL = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}";
    private static final int CHUNK_SIZE = 1024 * 1024; // 1024 KB chunks
    private static final HexFormat hexFormat = HexFormat.of();

    public static String generateSecurePassword(int length) {
        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder();

        while (password.length() < length) {
            int idx = random.nextInt(CHARACTER_POOL.length());
            password.append(CHARACTER_POOL.charAt(idx));
        }

        return password.toString();
    }

    public static SecretKey deriveKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty.");
        }
        System.out.println("Deriving secure encryption key from password using PBKDF2 with 1,000,000 rounds...");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_SIZE);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    public static void encryptFile(String inputFile, String outputFile, String userPassword) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_SIZE];
        random.nextBytes(salt);

        byte[] nonce = new byte[NONCE_SIZE];
        random.nextBytes(nonce);

        String password = (userPassword == null || userPassword.isEmpty()) ? generateSecurePassword(PASSWORD_LENGTH) : userPassword;
        SecretKey key = deriveKey(password, salt);

        //Oracle JDK enforces a hard limit of 2 GB on input data for AES-GCM
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE, nonce));

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            fos.write(salt);
            fos.write(nonce);

            try (CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
                byte[] buffer = new byte[CHUNK_SIZE];
                int bytesRead;
                long totalBytesRead = 0;
                long inputFileLength = new File(inputFile).length();

                while ((bytesRead = fis.read(buffer)) != -1) {
                    cos.write(buffer, 0, bytesRead);
                    totalBytesRead += bytesRead;
                    System.out.print("\rEncrypting file... " + ((totalBytesRead * 100) / inputFileLength) + "% done");
                }
            }

            System.out.println("\nFile encrypted successfully.");
            System.out.println("Password: " + password);
        }
    }

    public static void decryptFile(String inputFile, String outputFile) throws Exception {
        Console console = System.console();
        if (console == null) {
            System.err.println("No console available to prompt for password.");
            return;
        }
        char[] passwordChars = console.readPassword("Enter the decryption password: ");
        if (passwordChars == null) {
            System.err.println("Decryption password not provided.");
            return;
        }
        String password = new String(passwordChars);

        try (FileInputStream fis = new FileInputStream(inputFile)) {
            byte[] salt = new byte[SALT_SIZE];
            if (fis.read(salt) != SALT_SIZE) throw new IOException("Could not read full salt.");

            byte[] nonce = new byte[NONCE_SIZE];
            if (fis.read(nonce) != NONCE_SIZE) throw new IOException("Could not read full nonce.");

            SecretKey key = deriveKey(password, salt);
            //Oracle JDK enforces a hard limit of 2 GB on input data for AES-GCM
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE, nonce));

            try (CipherInputStream cis = new CipherInputStream(fis, cipher);
                 FileOutputStream fos = new FileOutputStream(outputFile)) {

                byte[] buffer = new byte[CHUNK_SIZE];
                int bytesRead;
                long totalBytesRead = 0;
                long inputFileLength = new File(inputFile).length();

                while ((bytesRead = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                    totalBytesRead += bytesRead;
                    System.out.print("\rDecrypting file... " + ((totalBytesRead * 100) / inputFileLength) + "% done");
                }

                System.out.println("\nFile decrypted successfully.");
            } finally {
                Arrays.fill(passwordChars, ' ');
            }
        }
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: java CipherForge (-ef <input_file> <output_file> [-p <password>] | -df <input_file> <output_file>)");
            return;
        }

        try {
            if (args[0].equals("-ef")) {
                if (args.length >= 3) {
                    String inputFile = args[1];
                    String outputFile = args[2];
                    String password = null;
                    for (int i = 3; i < args.length; i++) {
                        if (args[i].equals("-p") && i + 1 < args.length) {
                            password = args[i + 1];
                            break;
                        }
                    }
                    long inputFileSize = new File(inputFile).length();
                    if (inputFileSize > 2L * 1024L * 1024L * 1024L) {
                        System.err.println("Error: Cannot encrypt files larger than 2GB");
                        return;
                    }
                    encryptFile(inputFile, outputFile, password);
                } else {
                    System.err.println("Usage: java CipherForge -ef <input_file> <output_file> [-p <password>]");
                }
            } else if (args[0].equals("-df")) {
                if (args.length == 3) {
                    String inputFile = args[1];
                    String outputFile = args[2];
                    long inputFileSize = new File(inputFile).length();
                    if (inputFileSize > 2L * 1024L * 1024L * 1024L) {
                        System.err.println("Error: Cannot decrypt files larger than 2GB");
                        return;
                    }
                    decryptFile(inputFile, outputFile);
                } else {
                    System.err.println("Usage: java CipherForge -df <input_file> <output_file>");
                }
            } else {
                System.err.println("Invalid option. Use -ef for encrypt or -df for decrypt.");
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}
