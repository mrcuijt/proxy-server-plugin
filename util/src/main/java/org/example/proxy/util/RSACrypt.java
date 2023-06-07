package org.example.proxy.util;

import java.security.PrivateKey;
import java.security.PublicKey;

public class RSACrypt {

  private PrivateKey privateKey;

  private PublicKey publicKey;

  public RSACrypt(String privateKey, String publicKey){
    this.privateKey = RSACryptUtil.getPrivateKey(privateKey);
    this.publicKey = RSACryptUtil.getPublicKey(publicKey);
  }

  public String encrypt(String input){
    return RSACryptUtil.rsa2048PrivateKeyEncrypt(privateKey, input);
  }

  public String encrypt(byte[] input){
    return RSACryptUtil.rsa2048PrivateKeyEncrypt(privateKey, input);
  }

  public byte[] decrypt(String input){
    return RSACryptUtil.rsa2048PublicKeyDecrypt(publicKey, input);
  }

  public byte[] decrypt(byte[] input){
    return RSACryptUtil.rsa2048PublicKeyDecrypt(publicKey, input);
  }

}