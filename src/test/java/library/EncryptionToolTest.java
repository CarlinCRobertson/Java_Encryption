package library;

import junit.framework.TestCase;
import java.util.Base64;

/**
 * EncryptionToolTest is a class designed to test the encryption and decryption functionality of this library
 *
 * @author Carlin Robertson
 */
public class EncryptionToolTest extends TestCase {

    /**
     * Testing String to be used for encryption and decryption within this class
     */
    private final String PLAIN_TEST_STRING = "I am a string";

    /**
     * Encrypted test string encoded into BASE64
     */
    private static final String ENCRYPTED_TEST_STRING = "jngztED1GV1dMlvumV1bQQ==";

    /**
     * Encryption algorithm used by the ciphers
     */
    private static final String ENCRYPTION_ALGORITHM = "AES";

    /**
     * Base64 encoded test secret key
     */
    private static final String BASE_ENCODED_TEST_SECRET_STRING = "3OoZpZGNuVgP3o4hzW4voA==";

    /**
     * Base64 encoded initialisation vector byte array
     */
    private static final String BASE_ENCODED_INIT_VECTOR = "CVWkH24s35k6Q7XOw8Jzpw==";

    /**
     * Test method to check whether string encryption works correctly.
     */
    public void testEncryptString() {

        EncryptionTool encryptionTool = new EncryptionTool();

        /* Encrypt the string */
        String encryptedTestString = encryptionTool.encryptString(PLAIN_TEST_STRING);

        // Retrieve initialisation vector for use in new ciphers / new encryption tool object
        byte[] initVector = Base64.getDecoder().decode(encryptionTool.getInitVectorAsString());

        // New encryption tool object to test consistency by passing in a recreated secretKey and an initialisation vector.
        EncryptionTool decryptionTool = new EncryptionTool(EncryptionUtils.reconstructSecretKey(ENCRYPTION_ALGORITHM, encryptionTool.getSecretKey().getEncoded()), initVector);

        /* Check that the decrypted string matches the string we started with. */
        assertEquals(PLAIN_TEST_STRING, decryptionTool.decryptString((encryptedTestString)));
    }

    /**
     * Test method to check whether string decryption works correctly.
     */
    public void testDecryptString() {

        /* Decode the initialisation vector from BASE64 (Human friendly) into a byte array to be passed to the decryption tool */
        byte[] initVector = Base64.getDecoder().decode(BASE_ENCODED_INIT_VECTOR);

        /* Instantiating a new EncryptionTool object using a recreated key and initialisation vector in order to decrypt the encrypted content */
        EncryptionTool decryptionTool = new EncryptionTool(EncryptionUtils.reconstructSecretKey(ENCRYPTION_ALGORITHM, BASE_ENCODED_TEST_SECRET_STRING), initVector);

        /* Assert that decrypting the encrypted test string matches the initial plain text string */
        assertEquals(decryptionTool.decryptString(ENCRYPTED_TEST_STRING), PLAIN_TEST_STRING);
    }
}