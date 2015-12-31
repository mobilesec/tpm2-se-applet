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
 * @author Endalkachew Asnake
 *
 */
public class TPM2_RSA_Key {
	
	private static final byte LENGTH_AUTH_VALUE = 32;
	
	// TODO determine the required length for certificate
	private static final short LENGTH_CERTIFICATE_BUFFER_RSA_KEY_1024 = 200;
	
	private static final short LENGTH_CERTIFICATE_BUFFER_RSA_KEY_2048 = 300; 
	
	/** The handle that identifies the key. */
	private short handleNumber;
	
	private byte handleType;
	
	/** The private part of the key. */
	private RSAPrivateCrtKey privateKey;
	
	/** The public part of the key. */
	private RSAPublicKey publicKey;
	
	/** The auth value of the key. */
	private byte[] authValue;
	
	private byte[] certificate;
	
	/** The attribute specifying the use of the key. (Sign, decrypt, restricted). */
	private byte attribute;
//TODO validate attribute before signing or decrpting.
	
	private Cipher cipher;
	
	private Signature signature;
	
	private short keySize;
	
	private boolean certificateAvailable = false;
	
 
	/**
	 * Public constructor.
	 * 
	 * @param keySize the size of the key.
	 * @param handleType the handle type.
	 * @param handleNumber the handle number.
	 * @param attribute the key attribute.
	 * @param authValueBuffer the buffer containing the auth value of the key.
	 * @param offset the offset in authValueBuffer where the auth value starts from.
	 * @param length the length of the auth value. (Default length of the auth value is 32 bytes. If the length is shorter the remaining bytes are filled with zeros..
	 */
	public TPM2_RSA_Key(short keySize, byte handleType, short handleNumber, byte attribute, byte[] authValueBuffer, short offset, short length){
		 
		
		this.handleType = handleType;
		this.handleNumber = handleNumber;
		this.attribute = attribute;
		this.keySize = keySize;
		
		privateKey = (RSAPrivateCrtKey) KeyBuilder.buildKey( KeyBuilder.TYPE_RSA_CRT_PRIVATE, keySize, false);
		publicKey = (RSAPublicKey) KeyBuilder.buildKey(
				KeyBuilder.TYPE_RSA_PUBLIC, keySize, false); 
		KeyPair keyPair ; 
		
		if(keySize ==  KeyBuilder.LENGTH_RSA_512){
			keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_512); 
		}else if(keySize == KeyBuilder.LENGTH_RSA_768){
			keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_768); 
		}else if(keySize == KeyBuilder.LENGTH_RSA_1024){
			keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1024);
			certificate = new byte[LENGTH_CERTIFICATE_BUFFER_RSA_KEY_1024];
		}else{
			keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
			certificate = new byte[LENGTH_CERTIFICATE_BUFFER_RSA_KEY_2048];
		}
		
		keyPair.genKeyPair();
		
		privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
		publicKey = (RSAPublicKey) keyPair.getPublic();
		
		cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		
		signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
		
		authValue = new byte[LENGTH_AUTH_VALUE]; 
		short lengthAuthValue = LENGTH_AUTH_VALUE;
		if(length > 0){
			if(length < LENGTH_AUTH_VALUE){
				lengthAuthValue = length;
			}
			Util.arrayCopy(authValueBuffer, offset, authValue, (short)0, lengthAuthValue);
		}
	}

	
	/**
	 * Performs decryption with private key.
	 * 
	 * @param inputBuffer the input buffer.
	 * @param inputOffset the offset inputBuffer where the input starts from.
	 * @param inputLength the input length.
	 * @param outputBuffer the output buffer.
	 * @param outputOffset the offset in outputBuffer to start writing from.
	 * @return the length of the response.
	 */
	public short decrypt(byte[] inputBuffer, short inputOffset, short inputLength, byte[] outputBuffer, short outputOffset){
		cipher.init(privateKey, Cipher.MODE_DECRYPT); 
		return cipher.doFinal(inputBuffer, inputOffset, inputLength, outputBuffer, outputOffset); 
	}
	
	/**
	 * Signs data.
	 * 
	 * @param inputBuffer the input buffer.
	 * @param inputOffset the offset inputBuffer where the input starts from.
	 * @param inputLength the input length.
	 * @param outputBuffer the output buffer.
	 * @param outputOffset the offset in outputBuffer to start writing from.
	 * @return the length of the response.
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
	 * Gets the public part of this key.
	 * 
	 * @return  the length of the public key.
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
	
	/**
	 * Gets the stored certificate value of the RSA public key.
	 * 
	 * @param outputBuffer
	 * 				the buffer to write the certificate value.
	 * @param outputOffset
	 * 				the offset in output buffer to start writing from.
	 * @return the new offset in output buffer.
	 */
	public short getPublicKeyCertificate(byte[] outputBuffer, short outputOffset){ 
		return Util.arrayCopy(certificate, (short)0, outputBuffer, outputOffset, (short)certificate.length);
	}
	
	/**
	 * Sets the RSA public key certificate value.
	 * 
	 * @param inputBuffer
	 * 				the input buffer to read the certificate value from.
	 * @param offset
	 * 				the offset in the input buffer to start reading from. 
	 */
	public void setPublicKeyCertificate(byte[] inputBuffer, short offset, short length){ 
		Util.arrayCopy(inputBuffer, offset, certificate, (short)0, (short)certificate.length);
		certificateAvailable = true;
	} 
	
	/**
	 * Checks if public key certificate is set.
	 * 
	 * @return true if the public key certificate is set, false otherwise.
	 */
	public boolean hasCertificate(){
		return certificateAvailable;
	}
}
