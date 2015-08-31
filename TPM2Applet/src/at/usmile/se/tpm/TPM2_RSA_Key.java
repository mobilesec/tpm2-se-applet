package at.usmile.se.tpm;

import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;
 
/**
 * Represents TPM2 RSA key.
 * 
 * @author endalkachew.asnake
 *
 */
public class TPM2_RSA_Key {
	
	private static final byte LENGTH_AUTH_VALUE = 32;
	
	/** The handle that identifies the key. */
	private short handleNumber;
	
	private byte handleType;
	
	/** The private part of the key. */
	private RSAPrivateCrtKey privateKey;
	
	/** The public part of the key. */
	private RSAPublicKey publicKey;
	
	/** The auth value of the key. */
	private byte[] authValue;
	
	/** The attribute specifiying the use of the key. (Sign, decrypt, restricted). */
	private byte attribute;
//TODO validate attribute before signing or decrpting.
	
	private Cipher cipher;
	
	private Signature signature;
	
	private short keySize;
	
	/**
	 * Public constructor: Initializes this key with the required key size.
	 * 
	 * @param keySize
	 * 				the size of the key.
	 */
	public TPM2_RSA_Key(short keySize, byte handleType, short handleNumber, byte attribute){
		authValue = new byte[LENGTH_AUTH_VALUE];
	
		this.handleType = handleType;
		this.handleNumber = handleNumber;
		this.attribute = attribute;
		this.keySize = keySize;
		
		privateKey = (RSAPrivateCrtKey) KeyBuilder.buildKey( KeyBuilder.TYPE_RSA_CRT_PRIVATE, keySize, false);
		publicKey = (RSAPublicKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_RSA_PUBLIC, keySize, false); 
		KeyPair keyPair ; 
		
		if(keySize == 512){
			keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_512);
		}else if(keySize == 768){
			keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_768);
		}else if(keySize == 1024){
			keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1024);
		}else{
			keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
		}
		
		keyPair.genKeyPair();
		
		privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
		publicKey = (RSAPublicKey) keyPair.getPublic();
		
		cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		
		signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
	}

	
	/**
	 * 
	 * @param inputBuffer
	 * @param inputOffset
	 * @param inputLength
	 * @param outputBuffer
	 * @param outputOffset
	 * @return
	 */
	public short decrypt(byte[] inputBuffer, short inputOffset, short inputLength, byte[] outputBuffer, short outputOffset){
		cipher.init(privateKey, Cipher.MODE_DECRYPT); 
		return cipher.doFinal(inputBuffer, inputOffset, inputLength, outputBuffer, outputOffset); 
	}
	
	/**
	 * 
	 * @param inputBuffer
	 * @param inputOffset
	 * @param inputLength
	 * @param outputBuffer
	 * @param outputOffset
	 * @return
	 */
	public short sign(byte[] inputBuffer, short inputOffset, short inputLength, byte[] outputBuffer, short outputOffset){
		signature.init(privateKey, Signature.MODE_SIGN); 
		return signature.sign(inputBuffer,inputOffset, inputLength, outputBuffer, outputOffset); 
	}
	
	/**
	 * Gets the auth value of the RSA key.
	 * 
	 * @param outputBuffer
	 * 				the buffer to write the auth value.
	 * @param outputOffset
	 * 				the offset in output buffer to start writing from.
	 * @return the new offset in output buffer.
	 */
	public short getAuthValue(byte[] outputBuffer, short outputOffset){
		return Util.arrayCopy(authValue, (short)0, outputBuffer, outputOffset, LENGTH_AUTH_VALUE);
	}

	/**
	 * Gets the handle number.
	 * 
	 * @return the handle
	 */
	public short getHandleNumber() {
		return handleNumber;
	}

	/**
	 * Sets the handle number.
	 * 
	 * @param handle the handle to set
	 */
	public void setHandleNumber(short handleNumber) {
		this.handleNumber = handleNumber;
	}

	/**
	 * @return  
	 */
	public short getPublicKey(byte[] outputBuffer, short outputOffset) {
		 return publicKey.getModulus(outputBuffer, outputOffset);
	} 
	
	/**
	 * Gets the size of the key in bytes.
	 * 
	 * @return the size of the key.
	 */
	public short getKeySize(){
		return (short)(keySize/8);
	}

}
