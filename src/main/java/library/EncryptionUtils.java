package library;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;

/**
 * This class allows functionality to perform often utilised encryption actions such as generating or rebuilding SecretKey objects quickly and efficiently
 *
 * @author Carlin Robertson
 */
class EncryptionUtils {

    /**
     * Default Key Size (128 bit)
     */
    private static final int DEFAULT_128_BIT_KEY_SIZE = 128;

    /**
     * Default constructor
     */
    public EncryptionUtils() {
    }

    /**
     * Generates a random 128 bit SecretKey object in the chosen algorithm
     *
     * @param algorithm The encryption algorithm used to create the SecretKey (i.e AES)
     * @return SecretKey object
     */
    public static SecretKey generateRandom128BitKey(String algorithm) {

        /* Generate Secret Key */
        KeyGenerator keyGenerator = null;

        try {
            keyGenerator = KeyGenerator.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        Objects.requireNonNull(keyGenerator).init(DEFAULT_128_BIT_KEY_SIZE);

        return keyGenerator.generateKey();

    }

    /**
     * @param algorithm The encryption algorithm used to create the SecretKey (i.e AES)
     * @param secretKeyEncoded Base64 encoded string containing the SecretKey byte array
     * @return reconstructed SecretKey object
     */
    static SecretKey reconstructSecretKey(String algorithm, String secretKeyEncoded) {

        byte[] secretKeyDecoded = Base64.getDecoder().decode(secretKeyEncoded);

        /* Use the byte array containing the decoded secret key and the algorithm for encryption to reconstruct a SecretKey object */
        return new SecretKeySpec(secretKeyDecoded, algorithm);

    }

    /**
     * @param algorithm The encryption algorithm used to create the SecretKey (i.e AES)
     * @param secretKeyDecoded byte array containing the SecretKey
     * @return reconstructed SecretKey object
     */
    static SecretKey reconstructSecretKey(String algorithm, byte[] secretKeyDecoded) {

        /* Use the byte array containing the decoded secret key and the algorithm for encryption to reconstruct a SecretKey object */
        return new SecretKeySpec(secretKeyDecoded, algorithm);

    }
}
