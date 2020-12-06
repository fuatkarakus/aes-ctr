package org.yeditepe.security.cipher;

import java.math.BigInteger;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.ArrayUtils;

/**
 * This class extends abstract Cipher class. It implements AES in counter mode.
 */
public class AesCtr {

    /**
     * Javax crypto instance.
     */
    protected Cipher m_cipher;

    /**
     * Javax secret key spec instance.
     */
    protected SecretKeySpec m_keySpec;
    /**
     * Secure random generator.
     */
    protected SecureRandom m_secureRandom;

    /**
     * Number of bytes in a block, which is constant for AES.
     */
    protected static int BLOCK_SIZE_BYTES = 16;

    /**
     * Number of bits in a block, which is constant for AES.
     */
    protected static int BLOCK_SIZE_BITS = 128;

    /**
     * Number of bytes in key.
     */
    protected int KEY_SIZE_BYTES;

    /**
     * Class constructor. Creates a Javax.Crypto.Cipher instance with AES in CTR<br>
     * mode, without any padding.
     * 
     * @param key Input key for the cipher. Should be 16, 24, or 32 bytes long
     * @throws Exception Throws exception if key length is not 16, 24, or 32
     *                   bytes.<br>
     *                   May throw exception based on Javax.Crypto classes.
     */
    public AesCtr(byte[] key) throws Exception {

        // check if input key is ok
        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new Exception("Key length should be 16, 24, or 32 bytes long");
        }

        // set key length
        KEY_SIZE_BYTES = key.length;

        // create secret key spec instance
        m_keySpec = new SecretKeySpec(key, "AES");

        // create cipher instance
        m_cipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding");

        // create secure random number generator instance
        m_secureRandom = new SecureRandom();
    }

    /**
     * Encrypts input data with AES CTR mode.
     * 
     * @param data Input byte array.
     * @return Encryption result.
     * @throws Exception Throws exception if there is no data to encrypt.<br>
     *                   May throw exception based on Javax.Crypto.Cipher class
     */
    public byte[] encrypt(byte[] data, byte[] dv) throws Exception {
        // check if there is data to encrypt
        if (data.length == 0) {
            throw new Exception("No data to encrypt");
        }

        // create iv
        byte[] iv = new byte[BLOCK_SIZE_BYTES];
        byte[] randomNumber = (new BigInteger(BLOCK_SIZE_BITS, m_secureRandom)).toByteArray();
        int a;
        for (a = 0; a < randomNumber.length && a < BLOCK_SIZE_BYTES; a++)
            iv[a] = randomNumber[a];
        for (; a < BLOCK_SIZE_BYTES; a++)
            iv[a] = 0;

        // init cipher instance
        m_cipher.init(Cipher.ENCRYPT_MODE, m_keySpec, new IvParameterSpec(dv));

        // return concatenation of iv + encrypted data
        return ArrayUtils.addAll(dv, m_cipher.doFinal(data));
    }

    /**
     * Decrypts input data with AES CTR mode
     * 
     * @param data Input byte array.
     * @return Decryption result.
     * @throws Exception Throws exception if there is no data to decrypt.<br>
     *                   May throw exception based on Javax.Crypto.Cipher class.
     */
    public byte[] decrypt(byte[] data) throws Exception {
        // call overriden function with offset = 0
        return decrypt(data, 0);
    }

    /**
     * Decrypts input data starting and including the offset index position<br>
     * with AES CTR mode.
     * 
     * @param data   Input byte array.
     * @param offset Offset to start decryption.
     * @return Decryption result.
     * @throws Exception Throws exception if there is no data to decrypt.<br>
     *                   Throws exception if offset is invalid.<br>
     *                   May throw exception based on Javax.Crypto.Cipher class.
     */
    public byte[] decrypt(byte[] data, int offset) throws Exception {
        // check if there is data to decrypt after the offset and iv
        if (data.length <= BLOCK_SIZE_BYTES + offset) {
            throw new Exception("No data to decrypt");
        }

        // get iv value from the beggining of data
        byte[] iv = new byte[BLOCK_SIZE_BYTES];
        System.arraycopy(data, offset, iv, 0, BLOCK_SIZE_BYTES);

        // init cipher instance
        m_cipher.init(javax.crypto.Cipher.DECRYPT_MODE, m_keySpec, new IvParameterSpec(iv));

        // return decrypted value
        return m_cipher.doFinal(data, (BLOCK_SIZE_BYTES + offset), data.length - (BLOCK_SIZE_BYTES + offset));
    }
}
