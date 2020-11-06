package org.yeditepe.security.cipher;

/**
 * Abstract class to perform encryption, decryption, and decryption by an offset.
 */
public abstract class Cipher
{
    /**
     * Default constructor.
     * @throws Exception
     */
    public Cipher() throws Exception
    {
    }


    /**
     * Encrypt input data.
     * @param data Input data.
     * @return Encryption result.
     * @throws Exception
     */
    public abstract byte[] encrypt(byte[] data) throws Exception;


    /**
     * Decrypt input data.
     * @param data Input data.
     * @return Decryption result.
     * @throws Exception
     */
    public abstract byte[] decrypt(byte[] data) throws Exception;


    /**
     * Decrypt input data starting from index offset.
     * @param data Input data.
     * @param offset Starting index for decryption.
     * @return Decryption result.
     * @throws Exception
     */
    public abstract byte[] decrypt(byte[] data, int offset) throws Exception;
}