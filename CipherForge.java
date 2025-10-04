import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Console;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class CipherForge {
    private static final int KEY_SIZE = 256;
    private static final int SALT_SIZE = 16;
    private static final int NONCE_SIZE = 12;
    private static final int TAG_SIZE = 128; // 128-bit authentication tag
    private static final int PASSWORD_LENGTH = 43;
    private static final int PBKDF2_ITERATIONS = 1000000;
    private static final String START_TAG = "-----BEGIN AES-GCM ENCRYPTED DATA-----";
    private static final String END_TAG = "-----END AES-GCM ENCRYPTED DATA-----";
    private static final String CHARACTER_POOL = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!#%&?.-"; // Expanded character pool
    private static final int CHUNK_SIZE = 64 * 1024; // 64 KB chunks, same as Python

    public static String generateSecurePassword(int length) {
        SecureRandom random = new SecureRandom();
        int poolSize = CHARACTER_POOL.length();
        StringBuilder password = new StringBuilder();

        while (password.length() < length) {
            int s = random.nextInt(poolSize);
            password.append(CHARACTER_POOL.charAt(s));
        }

        return password.toString();
    }

    public static SecretKey deriveKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be null or empty.");
        }
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

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE, nonce));

        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            fos.write(salt);
            fos.write(nonce);

            byte[] buffer = new byte[CHUNK_SIZE];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] ciphertext = cipher.update(buffer, 0, bytesRead);
                if (ciphertext != null) {
                    fos.write(ciphertext);
                }
            }
            byte[] finalCiphertext = cipher.doFinal();
            if (finalCiphertext != null) {
                fos.write(finalCiphertext);
            }

            // Prepare data for ASCII armoring
            byte[] encryptedData = Files.readAllBytes(Paths.get(outputFile));

            // Write ASCII armor to the output file
            StringBuilder armoredOutput = new StringBuilder();
            armoredOutput.append(START_TAG).append("\n");
			Base64.Encoder encoder = Base64.getMimeEncoder(76, "\n".getBytes());
            armoredOutput.append(encoder.encodeToString(encryptedData)).append("\n");
            armoredOutput.append(END_TAG).append("\n");

            Files.writeString(Paths.get(outputFile), armoredOutput.toString(), StandardCharsets.UTF_8);

            System.out.println("File encrypted successfully.");
            System.out.println("Password: " + password);

        } catch (IOException e) {
            System.err.println("Error during file encryption: " + e.getMessage());
            throw e;
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
            System.out.println("Decryption password not provided.");
            return;
        }
        String password = new String(passwordChars);

        try {
            String armoredContent = new String(Files.readAllBytes(Paths.get(inputFile)), StandardCharsets.UTF_8);
            if (!armoredContent.contains(START_TAG) || !armoredContent.contains(END_TAG)) {
                throw new IllegalArgumentException("Invalid format: ASCII armor tags missing.");
            }

            String base64Content = armoredContent.substring(armoredContent.indexOf(START_TAG) + START_TAG.length(), armoredContent.indexOf(END_TAG)).replaceAll("\\r?\\n", "").trim();
            byte[] combinedData = Base64.getDecoder().decode(base64Content);

            if (combinedData.length < SALT_SIZE + NONCE_SIZE) {
                throw new IllegalArgumentException("Invalid encrypted data format.");
            }

            byte[] salt = new byte[SALT_SIZE];
            byte[] nonce = new byte[NONCE_SIZE];
            byte[] ciphertext = new byte[combinedData.length - SALT_SIZE - NONCE_SIZE];

            System.arraycopy(combinedData, 0, salt, 0, SALT_SIZE);
            System.arraycopy(combinedData, SALT_SIZE, nonce, 0, NONCE_SIZE);
            System.arraycopy(combinedData, SALT_SIZE + NONCE_SIZE, ciphertext, 0, ciphertext.length);

            SecretKey key = deriveKey(password, salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE, nonce));

            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                byte[] buffer = new byte[CHUNK_SIZE + TAG_SIZE / 8]; // Adjusted buffer size for GCM
                int offset = 0;
                while (offset < ciphertext.length) {
                    int length = Math.min(CHUNK_SIZE + TAG_SIZE / 8, ciphertext.length - offset);
                    byte[] chunk = java.util.Arrays.copyOfRange(ciphertext, offset, offset + length);
                    byte[] decryptedChunk = cipher.update(chunk);
                    if (decryptedChunk != null) {
                        fos.write(decryptedChunk);
                    }
                    offset += length;
                }
                byte[] finalDecrypted = cipher.doFinal();
                if (finalDecrypted != null) {
                    fos.write(finalDecrypted);
                }
                System.out.println("File decrypted successfully.");

            } catch (IOException e) {
                System.err.println("Error during file decryption: " + e.getMessage());
                throw e;
            } catch (AEADBadTagException e) {
                System.err.println("Decryption failed: Incorrect password or corrupted data.");
                throw e;
            } finally {
                // Clear the password from memory
                java.util.Arrays.fill(passwordChars, ' ');
            }

        } catch (IOException e) {
            System.err.println("Error reading input file: " + e.getMessage());
            throw e;
        }
    }

    public static void main(String[] args) {
        // dummy change
        if (args.length < 2) {
            System.out.println("Usage: java CipherForge (-ef <input_file> <output_file> [-p <password>] | -df <input_file> <output_file>)");
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
                    encryptFile(inputFile, outputFile, password);
                } else {
                    System.out.println("Usage: java CipherForge -ef <input_file> <output_file> [-p <password>]");
                }
            } else if (args[0].equals("-df")) {
                if (args.length == 3) {
                    String inputFile = args[1];
                    String outputFile = args[2];
                    decryptFile(inputFile, outputFile);
                } else {
                    System.out.println("Usage: java CipherForge -df <input_file> <output_file>");
                }
            } else {
                System.out.println("Invalid option. Use -ef for encrypt or -df for decrypt.");
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}
