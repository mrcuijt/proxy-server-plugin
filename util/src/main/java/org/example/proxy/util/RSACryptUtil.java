package org.example.proxy.util;

import java.io.StringWriter;
import java.io.ByteArrayOutputStream;
import java.io.Reader;
import java.io.IOException;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;

import org.apache.commons.codec.binary.Base64;

public class RSACryptUtil {

  private static final String ALGORITHM = "RSA";
  private static final String ALGORITHM_PADDING = "RSA/ECB/PKCS1Padding";
  private static final String ALGORITHM_SHA1PRNG = "SHA1PRNG";

  // 分段加密，每次最大加密的长度 117 字节 RSA-Key Size(1024) 117
  private static final int RSA_1024_ENCRYPT_MAX_SIZE = 117;
  private static final int RSA_2048_ENCRYPT_MAX_SIZE = 245; // RSA-Key Size(2048) 245
  // 分段解密，每次最大解密的长度 128 字节 RSA-Key Size(1024) 128
  private static final int RSA_1024_DECRYPT_MAX_SIZE = 128;
  private static final int RSA_2048_DECRYPT_MAX_SIZE = 256; // RSA-Key Size(2048) 256

  public static KeyPair generateRSAKeyPair(){
    try {
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
      SecureRandom random = SecureRandom.getInstance(ALGORITHM_SHA1PRNG);
      // random.setSeed("seed".getBytes()); // 使用种子则生成相同的公钥和私钥
      keyGen.initialize(2048, random);
      return keyGen.generateKeyPair();
    } catch(Exception e){
      e.printStackTrace();
    }
    return null;
  }

  /* Public Key Encrypt */
  public static String rsa1024PublicKeyEncrypt(Key key, String input){
    return encrypt(key, input, RSA_1024_ENCRYPT_MAX_SIZE);
  }

  public static String rsa1024PublicKeyEncrypt(Key key, byte[] input){
    return encrypt(key, input, RSA_1024_ENCRYPT_MAX_SIZE);
  }

  public static String rsa2048PublicKeyEncrypt(Key key, String input){
    return encrypt(key, input, RSA_2048_ENCRYPT_MAX_SIZE);
  }

  public static String rsa2048PublicKeyEncrypt(Key key, byte[] input){
    return encrypt(key, input, RSA_2048_ENCRYPT_MAX_SIZE);
  }

  /* Private Key Encrypt */
  public static String rsa1024PrivateKeyEncrypt(Key key, String input){
    return encrypt(key, input, RSA_1024_ENCRYPT_MAX_SIZE);
  }

  public static String rsa1024PrivateKeyEncrypt(Key key, byte[] input){
    return encrypt(key, input, RSA_1024_ENCRYPT_MAX_SIZE);
  }

  public static String rsa2048PrivateKeyEncrypt(Key key, String input){
    return encrypt(key, input, RSA_2048_ENCRYPT_MAX_SIZE);
  }

  public static String rsa2048PrivateKeyEncrypt(Key key, byte[] input){
    return encrypt(key, input, RSA_2048_ENCRYPT_MAX_SIZE);
  }

  /* Public Key Decrypt */
  public static byte[] rsa1024PublicKeyDecrypt(Key key, String input){
    return decrypt(key, input, RSA_1024_DECRYPT_MAX_SIZE);
  }

  public static byte[] rsa1024PublicKeyDecrypt(Key key, byte[] input){
    return decrypt(key, input, RSA_1024_DECRYPT_MAX_SIZE);
  }

  public static byte[] rsa2048PublicKeyDecrypt(Key key, String input){
    return decrypt(key, input, RSA_2048_DECRYPT_MAX_SIZE);
  }

  public static byte[] rsa2048PublicKeyDecrypt(Key key, byte[] input){
    return decrypt(key, input, RSA_2048_DECRYPT_MAX_SIZE);
  }

  /* Private Key Decrypt */
  public static byte[] rsa1024PrivateKeyDecrypt(Key key, String input){
    return decrypt(key, input, RSA_1024_DECRYPT_MAX_SIZE);
  }

  public static byte[] rsa1024PrivateKeyDecrypt(Key key, byte[] input){
    return decrypt(key, input, RSA_1024_DECRYPT_MAX_SIZE);
  }

  public static byte[] rsa2048PrivateKeyDecrypt(Key key, String input){
    return decrypt(key, input, RSA_2048_DECRYPT_MAX_SIZE);
  }

  public static byte[] rsa2048PrivateKeyDecrypt(Key key, byte[] input){
    return decrypt(key, input, RSA_2048_DECRYPT_MAX_SIZE);
  }

  public static String encrypt(Key key, String input, int encryptMaxSize){
    byte[] datas = null;
    try {
      datas = input.getBytes("UTF-8");
    } catch(Exception e){
      e.printStackTrace();
    }
    return encrypt(key, datas, encryptMaxSize);
  }

  public static String encrypt(Key key, byte[] input, int encryptMaxSize){
    try {
      Cipher cipher = Cipher.getInstance(ALGORITHM_PADDING);
      cipher.init(Cipher.ENCRYPT_MODE, key);
      int offset = 0;
      byte[] buffer = new byte[1024];
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      while ((input.length - offset) > 0) {
        if ((input.length - offset) >= encryptMaxSize) {
          buffer = cipher.doFinal(input, offset, encryptMaxSize);
          baos.write(buffer);
          offset += encryptMaxSize;
        } else {
          int length = input.length - offset;
          buffer = cipher.doFinal(input, offset, length);
          baos.write(buffer);
          offset = input.length;
        }
      }
      return bencode(baos.toByteArray());
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  public static byte[] decrypt(Key key, String input, int decryptMaxSex){
    return decrypt(key, bdecode(input), decryptMaxSex);
  }

  public static byte[] decrypt(Key key, byte[] input, int decryptMaxSex){
    try {
      Cipher cipher = Cipher.getInstance(ALGORITHM_PADDING);
      cipher.init(Cipher.DECRYPT_MODE, key);
      int offset = 0;
      byte[] buffer = new byte[1024];
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      while ((input.length - offset) > 0) {
        if ((input.length - offset) >= decryptMaxSex) {
          buffer = cipher.doFinal(input, offset, decryptMaxSex);
          baos.write(buffer);
          offset += decryptMaxSex;
        } else {
          int length = input.length - offset;
          buffer = cipher.doFinal(input, offset, length);
          baos.write(buffer);
          offset = input.length;
        }
      }
      return baos.toByteArray();
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  public static PrivateKey getPrivateKey(String privateKey){
    try {
      return getPrivateKey(bdecode(privateKey));
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  public static PrivateKey getPrivateKey(byte[] privateKey){
    try {
      KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
      return kf.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

//  public static PublicKey generatePublicKey(PrivateKey privateKey){
//    
//  }

  public static PublicKey getPublicKey(String publicKey){
    try {
      KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
      return getPublicKey(bdecode(publicKey));
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  public static PublicKey getPublicKey(byte[] publicKey){
    try {
      KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
      return kf.generatePublic(new X509EncodedKeySpec(publicKey));
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  public static String bencode(byte[] bytes) {
    return Base64.encodeBase64String(bytes);
  }

  public static byte[] bdecode(String input) {
    return Base64.decodeBase64(input);
  }
}