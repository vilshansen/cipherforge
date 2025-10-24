import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.nio.charset.StandardCharsets;

// Future improvements:
//  - Use Argon2 for key derivation instead of PBKDF2
//  - Implement multi-threaded encryption/decryption for large files
//  - Consider AEAD modes other than GCM, such as AES-GCM-SIV
public class CipherForge {
    private static final int KEY_SIZE = 256;
    private static final int SALT_SIZE = 16;
    private static final int NONCE_SIZE = 12;
    private static final int TAG_SIZE = 128; // 128-bit authentication tag
    private static final int PASSWORD_LENGTH = 32;
    private static final int PBKDF2_ITERATIONS = 1000000;
    private static final String CHARACTER_POOL = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}";
    private static final int CHUNK_SIZE = 1024 * 1024; // 1024 KB chunks
    private static final byte[] FILE_MAGIC = "CIPHERFORGE-V00001".getBytes(StandardCharsets.UTF_8);


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
        System.out.println("Deriving secure encryption key from password using PBKDF2...");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_SIZE);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            SecretKey tmp = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
            return tmp;
        } finally {
            // Clear password material in spec if possible
            try {
                spec.clearPassword();
            } catch (Exception ignored) {}
        }
    }

    public static void encryptFile(String inputFile, String outputFile, String userPassword) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_SIZE];
        random.nextBytes(salt);

        byte[] nonce = new byte[NONCE_SIZE];
        random.nextBytes(nonce);

        String password = (userPassword == null || userPassword.isEmpty()) ? generateSecurePassword(PASSWORD_LENGTH) : userPassword;
        SecretKey key = deriveKey(password, salt);

        // IMPORTANT: do NOT log generated password to stdout in real use.
        if (userPassword == null || userPassword.isEmpty()) {
            System.err.println("Warning: a random password was generated. Store it securely (not in logs): " + password);
            System.err.println("If you want to provide a password, use -p <password>");
        }

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile);
             DataOutputStream dos = new DataOutputStream(fos)) {

            // Write versioned header: magic, iterations, salt len+salt, nonce len+nonce, original filename (UTF)
            dos.write(FILE_MAGIC);
            dos.writeInt(PBKDF2_ITERATIONS);
            dos.writeInt(salt.length);
            dos.write(salt);
            dos.writeInt(nonce.length);
            dos.write(nonce);
            dos.writeUTF(new File(inputFile).getName());
            dos.flush();

            // Use header+filename as AAD
            ByteArrayOutputStream headerStream = new ByteArrayOutputStream();
            try (DataOutputStream hdos = new DataOutputStream(headerStream)) {
                hdos.write(FILE_MAGIC);
                hdos.writeInt(PBKDF2_ITERATIONS);
                hdos.writeInt(salt.length);
                hdos.write(salt);
                hdos.writeInt(nonce.length);
                hdos.write(nonce);
                hdos.writeUTF(new File(inputFile).getName());
                hdos.flush();
            }
            byte[] aad = headerStream.toByteArray();

            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE, nonce));
            cipher.updateAAD(aad);

            try (CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
                byte[] buffer = new byte[CHUNK_SIZE];
                int bytesRead;
                long totalBytesRead = 0;
                long inputFileLength = new File(inputFile).length();

                while ((bytesRead = fis.read(buffer)) != -1) {
                    cos.write(buffer, 0, bytesRead);
                    totalBytesRead += bytesRead;
                    System.out.print("\rEncrypting file... " + ((totalBytesRead * 100) / Math.max(1, inputFileLength)) + "% done");
                }
            }

            System.out.println("\nFile encrypted successfully.");
        } finally {
            // attempt to zero key material
            try {
                byte[] kb = key.getEncoded();
                if (kb != null) Arrays.fill(kb, (byte) 0);
            } catch (Exception ignored) {}
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

        try (FileInputStream fis = new FileInputStream(inputFile);
             DataInputStream dis = new DataInputStream(fis)) {

            // Read header
            byte[] magic = new byte[FILE_MAGIC.length];
            dis.readFully(magic);
            if (!java.util.Arrays.equals(magic, FILE_MAGIC)) {
                throw new IOException("Unrecognized file format");
            }
            int iterations = dis.readInt();
            int saltLen = dis.readInt();
            if (saltLen <= 0 || saltLen > 1024) throw new IOException("Invalid salt length");
            byte[] salt = new byte[saltLen];
            dis.readFully(salt);

            int nonceLen = dis.readInt();
            if (nonceLen <= 0 || nonceLen > 1024) throw new IOException("Invalid nonce length");
            byte[] nonce = new byte[nonceLen];
            dis.readFully(nonce);

            String originalName = dis.readUTF();

            // Rebuild AAD exactly as encryption
            ByteArrayOutputStream headerStream = new ByteArrayOutputStream();
            try (DataOutputStream hdos = new DataOutputStream(headerStream)) {
                hdos.write(magic);
                hdos.writeInt(iterations);
                hdos.writeInt(saltLen);
                hdos.write(salt);
                hdos.writeInt(nonceLen);
                hdos.write(nonce);
                hdos.writeUTF(originalName);
                hdos.flush();
            }
            byte[] aad = headerStream.toByteArray();

            SecretKey key = deriveKey(password, salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            try {
                cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE, nonce));
                cipher.updateAAD(aad);

                try (CipherInputStream cis = new CipherInputStream(fis, cipher);
                     FileOutputStream fos = new FileOutputStream(outputFile)) {

                    byte[] buffer = new byte[CHUNK_SIZE];
                    int bytesRead;
                    long totalBytesRead = 0;
                    long inputFileLength = new File(inputFile).length();

                    while ((bytesRead = cis.read(buffer)) != -1) {
                        fos.write(buffer, 0, bytesRead);
                        totalBytesRead += bytesRead;
                        System.out.print("\rDecrypting file... " + ((totalBytesRead * 100) / Math.max(1, inputFileLength)) + "% done");
                    }

                    System.out.println("\nFile decrypted successfully.");
                }
            } finally {
                // zero key bytes
                try {
                    byte[] kb = key.getEncoded();
                    if (kb != null) Arrays.fill(kb, (byte) 0);
                } catch (Exception ignored) {}
            }
        } finally {
            Arrays.fill(passwordChars, ' ');
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
