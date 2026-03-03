package dk.cipherforge;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

/**
 * CipherForge - A secure file encryption/decryption tool using AES-256-GCM
 * 
 * Security features:
 * - AES-256-GCM authenticated encryption
 * - PBKDF2 key derivation with 1,000,000 iterations
 * - Random salt and nonce generation
 * - Memory clearing for sensitive data
 * - Constant-time comparisons
 * - Secure console password input
 * 
 * File naming:
 * - Encrypted files get .cfo extension
 * - Decrypted files have .cfo extension removed
 */
public class CipherForge {
    // Cryptographic constants
    private static final int KEY_SIZE = 256;
    private static final int SALT_SIZE = 32;
    private static final int NONCE_SIZE = 12;
    private static final int TAG_SIZE = 128; // 128-bit authentication tag
    private static final int PBKDF2_ITERATIONS = 1_000_000;
    private static final int CHUNK_SIZE = 1024 * 1024; // 1 MB chunks
    private static final byte[] FILE_MAGIC_MARKER = "CIPHERFORGE-V00001".getBytes(StandardCharsets.UTF_8);
    private static final String ENCRYPTED_EXTENSION = ".cfo";

    // ======================== Utility Methods ========================

    /**
     * Secure comparison to prevent timing attacks
     */
    private static boolean secureEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    /**
     * Secure comparison for char arrays (passwords)
     */
    private static boolean secureEquals(char[] a, char[] b) {
        if (a == null || b == null) {
            return false;
        }
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    /**
     * Clear sensitive byte arrays
     */
    private static void clearBytes(byte[]... arrays) {
        for (byte[] array : arrays) {
            if (array != null) {
                Arrays.fill(array, (byte) 0);
            }
        }
    }

    /**
     * Clear sensitive char arrays
     */
    private static void clearChars(char[]... arrays) {
        for (char[] array : arrays) {
            if (array != null) {
                Arrays.fill(array, '\0');
            }
        }
    }

    /**
     * Get output filename for encryption
     */
    private static String getEncryptedOutputFile(String inputFile) {
        return inputFile + ENCRYPTED_EXTENSION;
    }

    /**
     * Get output filename for decryption
     */
    private static String getDecryptedOutputFile(String inputFile) throws IOException {
        if (!inputFile.endsWith(ENCRYPTED_EXTENSION)) {
            throw new IOException("Input file must have " + ENCRYPTED_EXTENSION + " extension for decryption.");
        }
        return inputFile.substring(0, inputFile.length() - ENCRYPTED_EXTENSION.length());
    }

    /**
     * Check if we would overwrite an existing file
     */
    private static void checkOverwrite(String outputFile) throws IOException {
        File file = new File(outputFile);
        if (file.exists()) {
            Console console = System.console();
            if (console != null) {
                String response = console.readLine("Warning: " + outputFile + " already exists. Overwrite? (y/N): ");
                if (response == null || !response.trim().equalsIgnoreCase("y")) {
                    throw new IOException("Operation cancelled by user.");
                }
            }
        }
    }

    // ======================== Cryptographic Core ========================

    /**
     * Derive an AES key from a password using PBKDF2.
     * Uses SHA-512 because it is significantly harder for many current GPUs
     * to parallelize efficiently than SHA-256.
     */
    public static SecretKey deriveKey(char[] password, byte[] salt) 
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password cannot be null or empty.");
        }
        
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, KEY_SIZE);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            spec.clearPassword();
        }
    }

    // ======================== Encryption ========================

    /**
     * Encrypt a file with password-based AES-256-GCM
     */
    public static void encryptFile(String inputFile, char[] userPassword) throws Exception {
        // Validate input
        File input = new File(inputFile);
        if (!input.exists()) {
            throw new IOException("Input file does not exist: " + inputFile);
        }
        if (!input.isFile()) {
            throw new IOException("Input is not a regular file: " + inputFile);
        }

        if (userPassword == null || userPassword.length == 0) {
            throw new IllegalArgumentException("Password is required for encryption. Please provide a password.");
        }

        String outputFile = getEncryptedOutputFile(inputFile);
        checkOverwrite(outputFile);

        // Generate random salt and nonce
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_SIZE];
        byte[] nonce = new byte[NONCE_SIZE];
        random.nextBytes(salt);
        random.nextBytes(nonce);

        SecretKey key = null;
        try {
            // Derive key from password
            key = deriveKey(userPassword, salt);

            // Initialize cipher
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            
            try (FileInputStream fis = new FileInputStream(inputFile);
                 FileOutputStream fos = new FileOutputStream(outputFile);
                 DataOutputStream dos = new DataOutputStream(fos)) {

                // Build and write header (also used as AAD)
                byte[] aad = buildHeader(inputFile, salt, nonce);
                dos.write(aad);
                dos.flush();

                // Initialize cipher with AAD
                cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE, nonce));
                cipher.updateAAD(aad);

                // Encrypt file content
                try (CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
                    byte[] buffer = new byte[CHUNK_SIZE];
                    int bytesRead;
                    
                    while ((bytesRead = fis.read(buffer)) != -1) {
                        cos.write(buffer, 0, bytesRead);
                    }
                }
            }
            
            System.out.println("File encrypted successfully: " + outputFile);
            
        } finally {
            // Clear sensitive data
            if (key != null) {
                byte[] keyBytes = key.getEncoded();
                if (keyBytes != null) {
                    clearBytes(keyBytes);
                }
            }
            clearChars(userPassword);
            clearBytes(salt, nonce);
        }
    }

    /**
     * Build the file header (also used as AAD)
     */
    private static byte[] buildHeader(String inputFile, byte[] salt, byte[] nonce) throws IOException {
        ByteArrayOutputStream headerStream = new ByteArrayOutputStream();
        try (DataOutputStream headerDos = new DataOutputStream(headerStream)) {
            headerDos.write(FILE_MAGIC_MARKER);
            headerDos.writeInt(PBKDF2_ITERATIONS);
            headerDos.writeInt(salt.length);
            headerDos.write(salt);
            headerDos.writeInt(nonce.length);
            headerDos.write(nonce);
            headerDos.writeUTF(new File(inputFile).getName());
            headerDos.flush();
        }
        return headerStream.toByteArray();
    }

    // ======================== Decryption ========================

    /**
     * Decrypt a file with password-based AES-256-GCM
     */
    public static void decryptFile(String inputFile) throws Exception {
        // Validate input
        File input = new File(inputFile);
        if (!input.exists()) {
            throw new IOException("Input file does not exist: " + inputFile);
        }
        if (!input.isFile()) {
            throw new IOException("Input is not a regular file: " + inputFile);
        }

        String outputFile = getDecryptedOutputFile(inputFile);
        checkOverwrite(outputFile);

        // Get password from console
        Console console = System.console();
        if (console == null) {
            throw new IOException("No console available for secure password input.");
        }

        char[] passwordChars = console.readPassword("Enter decryption password: ");
        if (passwordChars == null || passwordChars.length == 0) {
            throw new IllegalArgumentException("Password cannot be empty.");
        }
    
        byte[] salt = null;
        byte[] nonce = null;
        SecretKey key = null;
        
        try (FileInputStream fis = new FileInputStream(inputFile);
             DataInputStream dis = new DataInputStream(fis)) {

            // Read and validate header
            HeaderData header = readAndValidateHeader(dis);
            salt = header.salt;
            nonce = header.nonce;

            // Rebuild AAD exactly as encryption
            byte[] aad = rebuildAAD(header);

            // Derive key and initialize cipher
            key = deriveKey(passwordChars, salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_SIZE, nonce));
            cipher.updateAAD(aad);

            // Decrypt to temp file
            decryptToTempFile(fis, cipher, outputFile);
            
            System.out.println("File decrypted successfully: " + outputFile);
            
        } catch (IOException e) {
            throw new IOException("Decryption failed: " + e.getMessage(), e);
        } finally {
            // Clear all sensitive data
            clearChars(passwordChars);
            if (salt != null) clearBytes(salt);
            if (nonce != null) clearBytes(nonce);
            if (key != null) {
                byte[] keyBytes = key.getEncoded();
                if (keyBytes != null) clearBytes(keyBytes);
            }
        }
    }

    /**
     * Read and validate file header
     */
    private static HeaderData readAndValidateHeader(DataInputStream dis) throws IOException {
        // Read and verify magic marker
        byte[] magic = new byte[FILE_MAGIC_MARKER.length];
        dis.readFully(magic);
        if (!secureEquals(magic, FILE_MAGIC_MARKER)) {
            throw new IOException("Invalid file format: unrecognized header.");
        }
        
        // Read iterations (validate but don't use - fixed constant)
        int iterations = dis.readInt();
        if (iterations != PBKDF2_ITERATIONS) {
            throw new IOException("File created with different PBKDF2 iterations.");
        }
        
        // Read salt
        int saltLen = dis.readInt();
        if (saltLen <= 0 || saltLen > 1024) {
            throw new IOException("Invalid file format.");
        }
        byte[] salt = new byte[saltLen];
        dis.readFully(salt);
        
        // Read nonce
        int nonceLen = dis.readInt();
        if (nonceLen <= 0 || nonceLen > 1024) {
            throw new IOException("Invalid file format.");
        }
        byte[] nonce = new byte[nonceLen];
        dis.readFully(nonce);

        // Read original filename
        String originalName = dis.readUTF();

        return new HeaderData(magic, iterations, salt, nonce, originalName);
    }

    /**
     * Rebuild AAD from header data
     */
    private static byte[] rebuildAAD(HeaderData header) throws IOException {
        ByteArrayOutputStream headerStream = new ByteArrayOutputStream();
        try (DataOutputStream hdos = new DataOutputStream(headerStream)) {
            hdos.write(header.magic);
            hdos.writeInt(header.iterations);
            hdos.writeInt(header.salt.length);
            hdos.write(header.salt);
            hdos.writeInt(header.nonce.length);
            hdos.write(header.nonce);
            hdos.writeUTF(header.originalName);
            hdos.flush();
        }
        return headerStream.toByteArray();
    }

    /**
     * Decrypt to a temporary file and atomically move to destination
     */
    private static void decryptToTempFile(FileInputStream fis, Cipher cipher, String outputFile) throws IOException {
        Path outputPath = Paths.get(outputFile).toAbsolutePath();
        Path tempFile = Files.createTempFile(outputPath.getParent(), "cipherforge_decrypt_", ".tmp");
        
        try {
            try (CipherInputStream cis = new CipherInputStream(fis, cipher);
                 FileOutputStream fos = new FileOutputStream(tempFile.toFile())) {

                byte[] buffer = new byte[CHUNK_SIZE];
                int bytesRead;
                
                while ((bytesRead = cis.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                }
                fos.flush();
            }

            // If we get here, authentication succeeded
            Files.move(tempFile, outputPath, StandardCopyOption.REPLACE_EXISTING);
            
        } catch (Exception e) {
            Files.deleteIfExists(tempFile);
            throw new IOException("Decryption failed: " + e.getMessage(), e);
        }
    }

    /**
     * Simple data class for header components
     */
    private static class HeaderData {
        final byte[] magic;
        final int iterations;
        final byte[] salt;
        final byte[] nonce;
        final String originalName;

        HeaderData(byte[] magic, int iterations, byte[] salt, byte[] nonce, String originalName) {
            this.magic = magic;
            this.iterations = iterations;
            this.salt = salt;
            this.nonce = nonce;
            this.originalName = originalName;
        }
    }

    // ======================== Main Entry Point ========================

    public static void main(String[] args) {
        if (args.length < 1) {
            printUsage();
            return;
        }

        try {
            String command = args[0];
            
            // Check for help first, regardless of argument count
            if ("--help".equals(command) || "-h".equals(command) || "-?".equals(command)) {
                printDetailedHelp();
                return;
            }
            
            // Now check for minimum arguments for other commands
            if (args.length < 2) {
                printUsage();
                return;
            }
            
            if ("-e".equals(command)) {
                handleEncrypt(args);
            } else if ("-d".equals(command)) {
                handleDecrypt(args);
            } else {
                System.err.println("Invalid option: " + command);
                printUsage();
                System.exit(1);
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void printUsage() {
        System.err.println("CipherForge - File encryption/decryption tool");
        System.err.println("Usage: java CipherForge (-e <input_file> | -d <input_file> | --help)");
        System.err.println("  -e <file>: Encrypt file (adds .cfo extension)");
        System.err.println("  -d <file>: Decrypt file (removes .cfo extension)");
        System.err.println("  --help, -h: Show detailed help with technical specifications");
        System.err.println("");
        System.err.println("Examples:");
        System.err.println("  java CipherForge -e secret.txt      # Creates secret.txt.cfo");
        System.err.println("  java CipherForge -d secret.txt.cfo  # Creates secret.txt");
    }

    private static void printDetailedHelp() {
        System.err.println("╔══════════════════════════════════════════════════════════════╗");
        System.err.println("║                     CipherForge - Technical Details          ║");
        System.err.println("╚══════════════════════════════════════════════════════════════╝");
        System.err.println("");
        System.err.println("ALGORITHMS:");
        System.err.println("  ┌─────────────────────────────────────────────────────────┐");
        System.err.println("  │ Encryption  : AES-256-GCM (Galois/Counter Mode)         │");
        System.err.println("  │ Key Derivation: PBKDF2-HMAC-SHA512 with 1,000,000 iters │");
        System.err.println("  │ Randomness  : Java SecureRandom (cryptographically      │");
        System.err.println("  │              secure pseudo-random number generator)     │");
        System.err.println("  │ Authentication: 128-bit GCM authentication tag          │");
        System.err.println("  └─────────────────────────────────────────────────────────┘");
        System.err.println("");
        System.err.println("FILE FORMAT (.cfo):");
        System.err.println("  ┌─────────────────────────────────────────────────────────┐");
        System.err.println("  │ All multi-byte values are stored in big-endian order    │");
        System.err.println("  ├─────────────────────────────────────────────────────────┤");
        System.err.println("  │ Offset  │ Field          │ Size    │ Description        │");
        System.err.println("  ├─────────┼────────────────┼─────────┼────────────────────┤");
        System.err.println("  │ 0x00    │ Magic Marker   │ 16 bytes│ CIPHERFORGE-V00001 │");
        System.err.println("  │ 0x10    │ PBKDF2 Iters   │ 4 bytes │ 1,000,000          │");
        System.err.println("  │ 0x14    │ Salt Length    │ 4 bytes │ Always 32          │");
        System.err.println("  │ 0x18    │ Salt           │ 32 bytes│ Random salt value  │");
        System.err.println("  │ 0x28    │ Nonce Length   │ 4 bytes │ Always 12          │");
        System.err.println("  │ 0x2C    │ Nonce          │ 12 bytes│ Random nonce       │");
        System.err.println("  │ 0x38    │ Filename Length│ 2 bytes │ Length of original │");
        System.err.println("  │ 0x3A    │ Filename       │ Variable│ Original filename  │");
        System.err.println("  │ varies  │ Encrypted Data │ Variable│ AES-256-GCM data   │");
        System.err.println("  │ end-16  │ GCM Tag        │ 16 bytes│ Authentication tag │");
        System.err.println("  └─────────────────────────────────────────────────────────┘");
        System.err.println("");
        System.err.println("SECURITY PROPERTIES:");
        System.err.println("  ✓ Confidentiality: AES-256 encryption");
        System.err.println("  ✓ Integrity: GCM authentication (tamper detection)");
        System.err.println("  ✓ Authentication: Password-based key derivation");
        System.err.println("  ✓ Side-channel resistant: Constant-time comparisons");
        System.err.println("  ✓ Memory safety: Keys and passwords zeroed after use");
        System.err.println("  ✓ Randomness: Cryptographically secure random numbers");
        System.err.println("");
        System.err.println("COMPATIBILITY:");
        System.err.println("  Files encrypted with this version use format v00001");
        System.err.println("  The format is designed to be forward-compatible");
        System.err.println("  All cryptographic parameters are stored in the header");
        System.err.println("");
        System.err.println("For basic usage, run without --help");
    }

    private static void handleEncrypt(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: java CipherForge -e <input_file>");
            return;
        }

        String inputFile = args[1];
        
        Console console = System.console();
        if (console == null) {
            throw new IOException("No console available for password input.");
        }

        char[] password = null;
        char[] passwordRepeat = null;
        
        try {
            // Get password
            char[] response = console.readPassword("Enter encryption password: ");
            if (response != null && response.length > 0) {
                password = response;
            } else if (response != null) {
                clearChars(response);
            }

            // Get password confirmation
            response = console.readPassword("Repeat encryption password: ");
            if (response != null && response.length > 0) {
                passwordRepeat = response;
            } else if (response != null) {
                clearChars(response);
            }
            
            // Validate passwords
            if (password == null || passwordRepeat == null) {
                throw new IllegalArgumentException("Password cannot be empty.");
            }
            
            if (!secureEquals(password, passwordRepeat)) {
                throw new IllegalArgumentException("Passwords do not match.");
            }

            // Encrypt
            encryptFile(inputFile, password);
            
        } finally {
            clearChars(password, passwordRepeat);
        }
    }

    private static void handleDecrypt(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: java CipherForge -d <input_file>");
            return;
        }

        String inputFile = args[1];
        
        decryptFile(inputFile);
    }
}
