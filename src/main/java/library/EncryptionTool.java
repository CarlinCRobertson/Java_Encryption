package library;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Logger;

/**
 *
 * Encryption Tool Class which can be instantiated either with no arguments or by passing in a SecretKey object.
 *
 * The purpose of this class is to be able to quickly encrypt and decrypt strings and similar in secure algorithms such as AES.
 * This class makes use of the javax.crypto library for encryption.
 *
 * @author Carlin Robertson
 *
 */
public class EncryptionTool {

    private int DEFAULT_KEY_SIZE = 128;

    /**
     * Secret Key used in encryption / decryption
     */
    private SecretKey secretKey;

    /**
     * Init vector in byte array format presented for input into an encryption or decryption cipher
     */
    private byte[] initVector;

    /**
     * Encryption cipher object used to encrypt
     */
    private Cipher encryptionCipher;

    /**
     * Decryption cipher object used to decrypt
     */
    private Cipher decryptionCipher;

    /**
     * Encryption Algorithm
     */
    private String ALGORITHM = "AES";

    /**
     * Encryption Mode
     */
    private String MODE = "CBC";

    /**
     * Encryption Padding
     */
    private String PADDING = "PKCS5PADDING";

    /**
     * Logger object
     */
    private Logger logger = Logger.getLogger(EncryptionTool.class.getName());


    /**
     * Standard constructor with no arguments.
     *
     * - Creates a random secret key object for the selected algorithm of default key size (128)
     * - Initialises both encryption and decryption ciphers
     *
     */
    EncryptionTool() {
        try {

            /* Generate Secret Key */
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
            keyGenerator.init(DEFAULT_KEY_SIZE);
            this.secretKey = keyGenerator.generateKey();

            /* Initialise the encryption and decryption ciphers */
            initialiseCiphers();

        } catch (NoSuchAlgorithmException e) {
            logger.warning("No Such Algorithm: " + ALGORITHM);
        }

    }

    /**
     * @param secretKey A SecretKey object used by the encryption and decryption ciphers.
     *
     * Overloaded constructor where SecretKey object is passed in. The purpose of this is to be able to decrypt previously encrypted text
     * by specifying the SecretKey used when instantiating the ciphers.
     *
     */
    EncryptionTool(SecretKey secretKey, byte[] initVector) {
            /* Generate Secret Key */
            this.secretKey = secretKey;

            /* Initialise the encryption and decryption ciphers */
            initialiseCiphers(initVector);

    }

    /**
     * @param stringToBeEncrypted String of plain text characters to be encrypted by the library
     * @return Encrypted string
     */
    public String encryptString(String stringToBeEncrypted) {
        byte[] byteData = stringToBeEncrypted.getBytes();
        String encryptedString = "";
        try {
            byte[] encryptedData = encryptionCipher.doFinal(byteData);
            Base64.Encoder encoder = Base64.getEncoder();

            /* Encode byte array into Base64 to create a human readable encrypted string */
            encryptedString = new String(encoder.encode(encryptedData));

        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return encryptedString;
    }


    /**
     * @param stringToBeDecrypted Encrypted string to be decrypted using cipher
     * @return Decrypted string
     */
    String decryptString(String stringToBeDecrypted) {
        String decryptedString = "";
        try {
            /* Decode the string from Base 64 */
            byte[] decodedString = Base64.getDecoder().decode(stringToBeDecrypted);

            /* Take the decoded byte array and decrypt it */
            byte[] decryptedBytes = decryptionCipher.doFinal(decodedString);

            /* Convert the decrypted byte array back into a human readable string */
            decryptedString = new String(decryptedBytes);
        }
        catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return decryptedString;
    }

    /**
     * @return secretKey object
     */
    public SecretKey getSecretKey() {
        return secretKey;
    }

    /**
     * @return String secret key in encoded Base 64
     */
    public String getSecretKeyAsString() {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    /**
     * @param secretKey secretKey object
     */
    public void setSecretKey(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    /**
     * Method with no parameters designed to initialise both the encryption and decryption ciphers
     */
    private void initialiseCiphers() {

        /* Generate Initialisation Vector */
        byte[] initVector = new byte[DEFAULT_KEY_SIZE / 8];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initVector);
        this.initVector = initVector;
        
        initialiseEncryptionCipher();
        initialiseDecryptionCipher();

    }

    /**
     * Method which takes the algorithm (i.e AES), encryption mode (i.e CBC) and padding, passing them into the encryption cipher during initialisation.
     */
    private void initialiseEncryptionCipher() {

        /* Initialise the encryption cipher */
        try {

            encryptionCipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
            encryptionCipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(initVector));

        } catch (NoSuchAlgorithmException e) {
            logger.warning("No such algorithm found when initialising encryption cipher: " + ALGORITHM);
        } catch (NoSuchPaddingException e) {
            logger.warning("Padding: " + PADDING + " does not exist. NoSuchPaddingException");
        } catch (InvalidAlgorithmParameterException e) {
            logger.warning("Algorithm parameters specified are invalid when initialising encryption cipher, printing stack trace: " + e.getMessage());
        } catch (InvalidKeyException e) {
            logger.warning("InvalidKeyException. Bad Key for encryption cipher with " + ALGORITHM + " algorithm.");
        }
    }

    /**
     * Method which takes the algorithm (i.e AES), encryption mode (i.e CBC) and padding, passing them into the decryption cipher during initialisation.
     */
    private void initialiseDecryptionCipher() {

        try {

        /* Initialise the decryption cipher */
        decryptionCipher = Cipher.getInstance(ALGORITHM + "/" + MODE + "/" + PADDING);
        decryptionCipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(initVector));

        } catch (NoSuchAlgorithmException e) {
            logger.warning("No such algorithm found when initialising encryption cipher: " + ALGORITHM);
           } catch (NoSuchPaddingException e) {
            logger.warning("Padding: " + PADDING + " does not exist. NoSuchPaddingException");
        } catch (InvalidAlgorithmParameterException e) {
            logger.warning("Algorithm parameters specified are invalid when initialising encryption cipher, printing stack trace: " + e.getMessage());
        } catch (InvalidKeyException e) {
            logger.warning("InvalidKeyException. Bad Key for encryption cipher with " + ALGORITHM + " algorithm.");
        }
    }

    /**
     * @param initVector initialisation vector required in order to reconstruct a previous key when using cipher block chaining (CBC) encryption mode.
     */
    private void initialiseCiphers(byte[] initVector) {

        this.initVector = initVector;

        initialiseEncryptionCipher();
        initialiseDecryptionCipher();

    }

    /**
     * @return Returns the initialisation vector used within cipher-block-chaining (CBC) encryption mode.
     */
    public byte[] getInitVector() {
        return initVector;
    }

    /**
     * @return Base64 encoded string containing the initialisation vector.
     */
    String getInitVectorAsString() {
        return Base64.getEncoder().encodeToString(getInitVector());
    }
}
