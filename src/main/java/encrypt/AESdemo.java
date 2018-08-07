package encrypt;


import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
import java.security.Security;
import java.security.SecureRandom;

import java.io.UnsupportedEncodingException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;


public class AESdemo {

    //KeyGenerator
    private KeyGenerator keygen;
    //SecretKey
    private SecretKey deskey;
    //Cipher
    private Cipher c;
    //
    private byte[] cipherByte;

    public AESdemo() throws NoSuchAlgorithmException, NoSuchPaddingException{

        keygen = KeyGenerator.getInstance("AES");

        c = Cipher.getInstance("AES");
    }

    /**
     *  Encrypt
     *
     * @param str
     * @return
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public byte[] Encrytor(byte[] str) throws InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        c.init(Cipher.ENCRYPT_MODE, deskey);
        byte[] src = str;
        cipherByte = c.doFinal(src);
        return cipherByte;
    }


    /**
     * Decrypt
     *
     * @param buff
     * @return
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public byte[] Decryptor(byte[] buff) throws InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        c.init(Cipher.DECRYPT_MODE, deskey);
        cipherByte = c.doFinal(buff);
        return cipherByte;
    }


    /**
     * jdk sha256
     * @param json input  json array
     */
    public byte[] jdkSha256(String json){
        try {
            MessageDigest me = MessageDigest.getInstance("SHA-256");
            me.update(json.getBytes("UTF-8"));
            byte[] h = me.digest();

            return h;
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     *  genKey
     *
     * @param str
     * @return
     */
    public void genKey(byte[] sk){
        keygen.init(128, new SecureRandom(sk));
        deskey = keygen.generateKey();
    }

    /**
     * @param args
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     */
    public static void main(String[] args) throws Exception {
        String user ="halo||340221199412200415||1236781263||fudan||2012";
        String msg ="www.suning.com/index.jsp";
        AESdemo cs = new AESdemo();
        byte[] h = cs.jdkSha256(user);
        cs.genKey(h);

        byte[] encontent = cs.Encrytor(msg.getBytes("UTF-8"));
        byte[] decontent = cs.Decryptor(encontent);
        System.out.println("msg:" + msg);
        System.out.println("cypher:" + new String(encontent));
        System.out.println("plaintext:" + new String(decontent));
    }


}
