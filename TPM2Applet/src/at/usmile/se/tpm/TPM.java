/**
 * 
 */
package at.usmile.se.tpm;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.MessageDigest;
import javacard.security.RandomData;

/**
 * TPM main implementation class.
 * 
 * @author Endalkachew Asnake
 * 
 */
public class TPM {

	/////////----- Start TPM Structure Constants-----////////

	/** TPM handle types. The type of the entity is indicated by the MSO (Most Significant octate) of its handle. */
	/** Handle type for PCR */
	private static final byte TPM_HT_PCR = 0x00;
 

	/** Permanent values. */
	private static final byte TPM_HT_PERMANENT = 0x40;  

	// Permanent handles that can not be changed type 0x40.

	/**
	 * A handle references the Storage Primary Seed (SPS), the ownerAuth, and the ownerPolicy.
	 */
	private static final short TPM_RH_OWNER = 0x0001;

	/**
	 * A handle associated with the null hierarchy, an EmptyAuth authValue, and
	 * an Empty Policy authPolicy.
	 */
	private static final short TPM_RH_NULL = 0x0007;

	/** Authorization value used to indicate a password authorization session */
	private static final short TPM_RS_PW = 0x0009;

	/**
	 * References the authorization associated with the dictionary attack
	 * lockout reset.
	 */
	private static final short TPM_RH_LOCKOUT = 0x000A;

	/**
	 * References the Endorsement Primary seed (EPS) endorsementAuth, and
	 * endorsementPolicy.
	 */
	private static final short TPM_RH_ENDORSEMENT = 0x000B;

	/**
	 * References the Platform Primary Seed (PPS), platformAuth, and
	 * platformPolicy.
	 */
	private static final short TPM_RH_PLATFORM = 0x000C;

	/**
	 * Start of a range of authorization values that are vendor-specific. A TPM
	 * may support any of the values in this range as are needed for
	 * vendor-specific purposes.
	 */
	private static final short TPM_RH_AUTH_00 = 0x0010;

	/** End of the range of vendor-specific authorization values. */
	private static final short TPM_RH_AUTH_FF = 0x010F;

	// Session handles type = 0x02
	/**
	 * HMAC Authorization Session assigned by the TPM when the session is
	 * created
	 */
	private static final byte TPM_HT_HMAC_SESSION = 0x02;

	/** The first HMAC session handle. */
	private static final short TPM_HT_HMAC_SESSION_FIRST = 0x0000;

	// TPM session type constants.

	/** Represents HMAC session. */
	private static final byte TPM_SE_HMAC = 0x00;
	private static final byte TPM_SE_POLICY_TRIAL = 0x01;
	private static final byte TPM_SE_TRIAL = 0x03;

	// ///////////////////////// TPM RC Constants ///////////////////////////
	private static final short TPM_RC_SUCCESS = 0x00;

	private static final short TPM_RC_BAD_TAG = 0x1E;

	// Set for all format 0 response codes.
	private static final short RC_VER1 = 0x0100;

	// //////// RC_VER1 response codes /////////
	// Format 0 response codes take the format of (RC_VER1 + RC).

	/** TPM not initialized. */
	private static final short TPM_RC_VER1_INITIALIZE = 0x0000;

	/** Commands not being accepted because of a TPM failure. */
	private static final short TPM_RC_VER1_FAILURE = 0x0001;

	/** CommandSize value is inconsistent with contents of the command buffer. */
	private static final short TPM_RC_VER1_COMMAND_SIZE = 0x0042;

	/** Command code not supported. */
	private static final short TPM_RC_VER1_COMMAND_CODE = 0x0043;

	/**
	 * Returned when an internal function cannot process a request due to an
	 * unspecified problem. This code is usually related to invalid parameters
	 * that are not properly filtered by the input unmarshaling code.
	 */
	private static final short TPM_RC_NORESULT = 0x0054;

	// //////// RC_FMT1 response codes /////////
	// Format 1 response codes take the format of (RC_FMT1 + RC).
	// Set for all format 1 response codes.
	private static final short RC_FMT1 = 0x0080;

	/** Asymmetric algorithm not supported or not correct. */
	private static final short TPM_RC_FMT1_ASYMMETRIC = 0x0001;

	/** Inconsistent attributes. */
	private static final short TPM_RC_FMT1_ATTRIBUTES = 0x0002;

	/** Hash algorithm not supported or not appropriate. */
	private static final short TPM_RC_FMT1_HASH = 0x0003;

	/** Value is out of range or is not correct for the context. */
	private static final short TPM_RC_FMT1_VALUE = 0x0004;

	/** Key size is not supported. */
	private static final short TPM_RC_FMT1_KEY_SIZE = 0x0007;

	/** Mode of operation is not supported. */
	private static final short TPM_RC_FMT1_MODE = 0x0009;

	/** the value of a size parameter is larger or smaller than allowed. */
	private static final short TPM_RC_FMT1_SIZE = 0x0015;

	/** The handle is not correct for the use. */
	private static final short TPM_RC_FMT1_HANDLE = 0x000B;

	private static final short TPM_RC_FMT1_RANGE = 0x000D;

	/* The authorization HMAC check failed and DA counter incremented. */
	private static final short TPM_RC_FMT1_AUTH_FAIL = 0x000E;

	/** Invalid nonce size. */
	private static final short TPM_RC_FMT1_NONCE = 0x000F;

	// /////// TPM Command Codes /////////
	// // TPM standard command are 4 bytes long. Values defined here use the two
	// list significant bytes only for implementation convenience.
	private static final short TPM_CC_Startup = 0x0144;

	private static final short TPM_CC_Shutdown = 0x0145;

	private static final short TPM_CC_PCR_Read = 0x017E;

	private static final short TPM_CC_PCR_Extend = 0x0182;

	private static final short TPM_CC_PCR_Reset = 0x013D;

	private static final short TPM_CC_PCR_SetAuthValue = 0x0183; 

	private static final short TPM_CC_Quote = 0x0158; 
	
	private static final short TPM_CC_ReadPublic = 0x0173;

	private static final short TPM_CC_StartAuthSession = 0x0176;
	
	private static final short TPM_CC_GetRandom = 0x017B;
	
	/** Custom command to store externally signed public key certificate of the endorsement key. */
	private static final short Custom_CC_Store_EndorcementCertificate = 0x0001;
	/** Custom command to read the public part of the endorsement key. */
	private static final short Custom_CC_read_endorsementPublicKey = 0x0002;
	
	// /////////// TPM label definitions ////////

	private static final byte[] ATH = new byte[] { 0x41, 0x54, 0x48, 0x00 };

	private static final byte[] CFB = new byte[] { 0x43, 0x46, 0x42, 0x00 };

	private static final short TPM_ST_ATTEST_QUOTE = (short) 0x8018;

	private static final byte[] TPM_GENERATED_VALUE = new byte[] { (byte) 0xff, (byte) 0x54, (byte) 0x43, (byte) 0x47 };

	private static final byte TPMI_YES = 1;
	private static final byte TPMI_NO = 0;

	/** TPM_SU Constants */
	/**
	 * on TPM2_Shutdown(), indicates that the TPM should prepare for loss of
	 * power and save state required for an orderly startup (TPM Reset).
	 */
	private static final short TPM_SU_CLEAR = 0;
	/**
	 * on TPM2_Shutdown(), indicates that the TPM should prepare for loss of
	 * power and save state required for an orderly startup (TPM Restart or TPM
	 * Resume).
	 */
	private static final short TPM_SU_STATE = 1;

	// Definition of (UINT16) TPM_ALG_ID Constants.

	/** Should not occur. */
	private static final short TPM_ALG_ERROR = 0x0000;

	/** The RSA algorithm. */
	private static final short TPM_ALG_RSA = 0x0001;

	/** The SHA1 algorithm. */
	private static final short TPM_ALG_SHA1 = 0x0004;

	/** Hash Message Authentication Code (HMAC) algorithm. */
	private static final short TPM_ALG_HMAC = 0x0005;

	/** Hash Message Authentication Code (HMAC) algorithm. */
	private static final short TPM_ALG_AES = 0x0006;

	/** the AES algorithm with various key sizes. */
	private static final short TPM_ALG_XOR = 0x0008;

	/** The XOR encryption algorithm. */
	private static final short TPM_ALG_SHA256 = 0x000B;

	/** The null algorithm. */
	private static final short TPM_ALG_NULL = 0x0010;

	private static final short TPM_ALG_RSASSA = 0x0014;

	// Symmetric algorithm operation modes.
	/** Output Feedback mode. */
	private static final short TPM_ALG_OFB = 0x0041;

	/** Cipher Block Chaining mode. */
	private static final short TPM_ALG_CBC = 0x0042;

	/** Cipher Feedback mode. */
	private static final short TPM_ALG_CFB = 0x0043;

	// TPM Command and Response tags
	private static final short TPM_ST_NO_SESSION = (short) 0x8001;

	private static final short TPM_ST_SESSION = (short) 0x8002;

	// ///////----- End TPM Structure Constants-----////////

	// /// Implementation specific constants and private members//////

	private static final short PCR_AUTH_VALUE_LENGTH = 32;

	private byte[] PCR_PROTECTION_GROUP_01_AUTH;

	private TPM2_PCR[] pcrList;

	private short pcrUpdateCounter;

	private short tpm_su;

	/** Length of place holder for Clock in TPMS_CLOCK_INFO. is not implemented. */
	private static final byte LENGTH_EMPTY_CLOCK_VALUE = 8;

	private static final byte LENGTH_FIRMWARE_VERSION = 8;

	/* Number of occurrences of TPM Reset since the last TPM2_Clear(). */
	private short tpmResetCount;

	/*
	 * number of times that TPM2_Shutdown() or _TPM_Hash_Start have occurred
	 * since the last TPM Reset or TPM2_Clear().
	 */
	private short tpmRestartCount;

	/** Version number of the firmware. */
	private short firmwareVersion;

	private TPM2_RSA_Key endorsementKeyPrimaryKey;
	private static short ENDORSEMENT_KEY_HANDLE_NUMBER = 1;

	private static final short TPM_RSA_KEY_SIZE = 2048;

	private static byte KEY_ATTRIBUTE_SIGN_AND_DECRYPT = 0x06;

	private TPMCommandProcessor tpmCommandProcessor;

	private TPM2Session tpm2Session;

	private static final byte MIN_PCR_SELECT_SIZE = 3;
	private static final byte PLATFORM_PCR_SIZE = 24; 
	private static final byte LENGTH_PCR_SELECTION_COUNT = 4;
	private static final byte LENGTH_TPM2B = 2;

	private static final short ALG_SHA256_OUTPUT_BITS_COUNT = 256;
	private static final short ALT_SHA256_OUTPUT_BYTES_COUNT = 32;
	private static final short ALG_SHA1_OUTPUT_BITS_COUNT = 160; 

	/** Defines length of default TPM Response codes. */
	private static final short LENGTH_TPM_RC_DEFAULT = 10;

	private static final short LENGTH_DEFAULT_COMMAND_HEADER = 10;

	private static final short OFFSET_TAG = 0;
	private static final byte LENGTH_TAG = 2;

	private static final short OFFSET_COMMAND_SIZE = 2;

	private static final short OFFSET_COMMAND_CODE = 6;
	private static final byte LENGTH_COMMAND_CODE = 4;

	/** The offset of the first handle in a command. */
	private final static short OFFSET_HANDLE_A = 10;

	/** Size of any TPM handle. */
	private static final byte TPM_HANDLE_SIZE = 4;

	private static final short OFFSET_RESPONSE_CODE = 6;
	private static final byte LENGTH_RESPONSE_CODE = 4;
	private static final byte LENGTH_RESPONSE_PARAMERTER_SIZE = 4;

	private final static byte LENGTH_RESPONSE_SIZE = 4;
	private final static byte LENGTH_DIGEST_COUNT = 4;
	private final static byte LENGTH_ALGORITHM_ID = 2;
	

	/** A flag used to indicate startup command is expected after TPM init. */
	private boolean startupCommandExpected = false;

	private RandomData randomData;

	
	/**
	 * Public constructor. Performs required memory and object initialization. 
	 */
	public TPM(byte[] buffer, short installParameterOffset, short installParamLength) {
		
		pcrList = new TPM2_PCR[] { new TPM2_PCR((short) 0, (short) 1), new TPM2_PCR((short) 1, (short) 1), new TPM2_PCR((short) 2, (short) 1), new TPM2_PCR((short) 3, (short) 1), new TPM2_PCR((short) 4, (short) 1),
									new TPM2_PCR((short) 5, (short) 1), new TPM2_PCR((short) 6, (short) 1), new TPM2_PCR((short) 7, (short) 1), new TPM2_PCR((short) 8, (short) 1), new TPM2_PCR((short) 9, (short) 1),
									new TPM2_PCR((short) 10, (short) 1),new TPM2_PCR((short) 11, (short) 1),new TPM2_PCR((short) 12, (short) 1),new TPM2_PCR((short) 13, (short) 1),new TPM2_PCR((short) 14, (short) 1),
									new TPM2_PCR((short) 15, (short) 1),new TPM2_PCR((short) 16, (short) 1),new TPM2_PCR((short) 17, (short) 1),new TPM2_PCR((short) 18, (short) 1),new TPM2_PCR((short) 19, (short) 1),
									new TPM2_PCR((short) 20, (short) 1),new TPM2_PCR((short) 21, (short) 1),new TPM2_PCR((short) 22, (short) 1),new TPM2_PCR((short) 23, (short) 1)};

		PCR_PROTECTION_GROUP_01_AUTH = new byte[PCR_AUTH_VALUE_LENGTH];

		tpmCommandProcessor = new TPMCommandProcessor();
		tpm2Session = new TPM2Session();

		tpm_su = TPM_SU_CLEAR;

		endorsementKeyPrimaryKey = new TPM2_RSA_Key(TPM_RSA_KEY_SIZE, TPM_HT_PERMANENT, ENDORSEMENT_KEY_HANDLE_NUMBER, KEY_ATTRIBUTE_SIGN_AND_DECRYPT, buffer, installParameterOffset, installParamLength);
		 
		randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
	}

	/**
	 * Initialize TPM to accept TPM2_Sartatup command. (Should be called before starting to send TPM commands.)
	 */
	public void initTpm() {
		// Other tpm init procedures can be added here.
		startupCommandExpected = true;
	}

	/**
	 * Write {@link RC_VER1} response to a buffer.
	 * 
	 * @param buffer
	 *            the buffer to write to.
	 * @param offset
	 *            offset in the buffer to start writing from.
	 * @param responseCode
	 *            the response code to write.
	 * @return the length of the response written.
	 */
	private short writeRcVer1(byte[] buffer, short offset, short responseCode) {
		short currentOffset = Util.setShort(buffer, offset, TPM_ST_NO_SESSION);
		currentOffset = Util.setShort(buffer, currentOffset, (short) 0);
		currentOffset = Util.setShort(buffer, currentOffset, LENGTH_TPM_RC_DEFAULT);
		currentOffset = Util.setShort(buffer, currentOffset, RC_VER1);
		currentOffset = Util.setShort(buffer, currentOffset, responseCode);
		return (short) (currentOffset - offset);
	}

	/**
	 * Write {@link RC_FMT1} response code to buffer.
	 * 
	 * @param buffer
	 *            the buffer to write to.
	 * @param offset
	 *            offset in the buffer to start writing from.
	 * @param responseCode
	 *            the response code to write.
	 * @return the length of the response written.
	 */
	private short writeRcFmt1(byte[] buffer, short offset, short responseCode) {
		short currentOffset = Util.setShort(buffer, offset, TPM_ST_NO_SESSION);
		currentOffset = Util.setShort(buffer, currentOffset, (short) 0);
		currentOffset = Util.setShort(buffer, currentOffset, LENGTH_TPM_RC_DEFAULT);
		currentOffset = Util.setShort(buffer, currentOffset, RC_FMT1);
		currentOffset = Util.setShort(buffer, currentOffset, responseCode);
		return (short) (currentOffset - offset);
	}

	/**
	 * Write TPM response header to buffer.
	 * 
	 * @param buffer
	 *            the buffer to write to.
	 * @param offset
	 *            offset in the buffer to start writing from.
	 * @param tag
	 *            the tag of the response.
	 * @param length
	 *            the length of the response.
	 * @param responseCode
	 *            the response code.
	 * @return the new offset in the buffer.
	 */
	private short writeRcHeader(byte[] buffer, short offset, short tag, short length, short responseCode) {
		short currentOffset = Util.setShort(buffer, offset, tag);
		currentOffset = Util.setShort(buffer, currentOffset, (short) 0);
		currentOffset = Util.setShort(buffer, currentOffset, length);
		currentOffset = Util.setShort(buffer, currentOffset, (short) 0);
		return Util.setShort(buffer, currentOffset, responseCode);
	}

	/**
	 * Write TPM RC success to a response buffer.
	 * 
	 * @param buffer
	 *            the buffer to write the response
	 * @param offset
	 *            offset in the buffer to start writing from.
	 * @param tag
	 *            the tag of the response.
	 * @return the length of the response.
	 */
	private short writeRcSuccess(byte[] buffer, short offset, short tag) {
		short currentOffset = writeRcHeader(buffer, offset, tag, LENGTH_TPM_RC_DEFAULT, TPM_RC_SUCCESS);
		return (short) (currentOffset - offset);
	}

	/**
	 * Write TPM RC bad tag to a response buffer.
	 * 
	 * @param buffer
	 *            the buffer to write the response
	 * @param offset
	 *            offset in the buffer to start writing from.
	 * @return the length of the response.
	 */
	private short writeRcBadTag(byte[] buffer, short offset) {
		short currentOffset = writeRcHeader(buffer, offset, TPM_ST_NO_SESSION, LENGTH_TPM_RC_DEFAULT, TPM_RC_BAD_TAG);
		return (short) (currentOffset - offset);
	}

	public short processCommand(byte[] buffer, short offset, short length, byte[] outputBuffer, short offsetOutput) {
		return tpmCommandProcessor.processCommand(buffer, offset, length, outputBuffer, offsetOutput);
	}

	/**
	 * Represents a TPM2 command processor.
	 */
	private class TPMCommandProcessor {

		/**
		 * Processes command and returns the response buffer.
		 * 
		 * @param buffer
		 *            the buffer containing the TPM command.
		 * @param offset
		 *            the offset tpm command starts from.
		 * @param length
		 *            the length of the command.
		 * @param responseBuffer
		 *            the response buffer.
		 * @param offsetResponse
		 *            the offset in response buffer to start writing from.
		 * @return the length of the response.
		 */
		public short processCommand(byte[] buffer, short offset, short length, byte[] responseBuffer, short offsetResponse) {

			// Perform header validation. 

			short commandTag = getCommandTag(buffer, offset);
			// Check tag.
			if (!hasValidTag(commandTag)) {
				return writeRcBadTag(responseBuffer, offsetResponse);
			}

			// Check length
			short expectedLength = getCommandLength(buffer, offset);
			if (length < expectedLength) {
				return writeRcVer1(responseBuffer, offsetResponse, TPM_RC_VER1_COMMAND_SIZE);
			}

			short commandCode = getCommandCode(buffer, offset);
			
			// Handle required configuration(Personalization of the TPM) before startup command.  
			// - Storing signed certificate for the keys used in this implementation.
			// - Setting Auth values for keys.
			if(startupCommandExpected){
				switch (commandCode) {
				case Custom_CC_read_endorsementPublicKey:
					return getEndorsementPublicKey(responseBuffer, offsetResponse); 
					
				case Custom_CC_Store_EndorcementCertificate:
					return storeEndorsementPublicKeyCertificate(buffer, offset, expectedLength, responseBuffer, offsetResponse);
					 
				default:
					break;
				}
			}

			// Return if startup command is not received when it is expected or is received when it is not expected.
			if (startupCommandExpected && commandCode != TPM_CC_Startup || !startupCommandExpected && commandCode ==TPM_CC_Startup) {
				return writeRcFmt1(responseBuffer, offsetResponse, TPM_RC_VER1_INITIALIZE);
			}

			// TODO mode check
			// TPM failure mode, tpm not initialized

			switch (commandCode) {

				case TPM_CC_Startup:
					return handleStartupCommand(buffer, offset, length, responseBuffer, offsetResponse);
	
				case TPM_CC_Shutdown:
					return handleShutdownCommand(buffer, offset, length, responseBuffer, offsetResponse);
	
				case TPM_CC_StartAuthSession:
					return tpm2Session.handleStartAuthSessionCommand(buffer, offset, length, responseBuffer, offsetResponse);
	
				case TPM_CC_PCR_Extend:
				case TPM_CC_PCR_SetAuthValue:
				case TPM_CC_PCR_Reset:
					if(commandTag  == TPM_ST_SESSION){ 
						return tpm2Session.handlePcrCommand(buffer, offset, length, commandCode, responseBuffer, offsetResponse);
					}else{
						return writeRcBadTag(responseBuffer, offsetResponse);
					} 
					
				case TPM_CC_PCR_Read:
					return handlePcrReadCommand(buffer, offset, length, responseBuffer, offsetResponse);
	
				case TPM_CC_Quote:
					if(commandTag == TPM_ST_SESSION){ 
						 return tpm2Session.handleQuoteCommand(buffer, offset, length, responseBuffer, offsetResponse);
					}else{
						return writeRcBadTag(responseBuffer, offsetResponse);
					} 
	
				case TPM_CC_ReadPublic:
					return handleReadPublicCommand(buffer, offset, length, responseBuffer, offsetResponse); 
					
				case TPM_CC_GetRandom:
					return handleGetRandomCommand(buffer, offset, length, responseBuffer, offsetResponse);
	
				default:
					// Unsupported command code.
					return writeRcVer1(responseBuffer, offsetResponse, TPM_RC_VER1_COMMAND_CODE);
			}

		}

		/**
		 * Validates a TPM structure tag.
		 * 
		 * @param tag
		 *            the tag to validate.
		 * @return true if tag is valid, false otherwise.
		 */
		private boolean hasValidTag(short tag) {
			return tag == TPM_ST_SESSION || tag == TPM_ST_NO_SESSION;
		}

		/**
		 * Gets the command tag from command buffer.
		 * 
		 * @param buffer
		 *            the buffer containing the command tag.
		 * @param offset
		 *            the offset in the buffer where the command starts from.
		 * @return the command tag.
		 */
		private short getCommandTag(byte[] buffer, short offset) {
			return Util.getShort(buffer, (short) (offset + OFFSET_TAG));
		}

		/**
		 * Gets the command length from command buffer. (TPM command size
		 * encoded in four bytes, This method returns the size encoded using the
		 * two list significant bytes)
		 * 
		 * @param buffer
		 *            the buffer containing the command.
		 * @param offset
		 *            the offset in the buffer where the command starts from.
		 * @return the command tag.
		 */
		private short getCommandLength(byte[] buffer, short offset) {
			return Util.getShort(buffer, (short) (offset + OFFSET_COMMAND_SIZE + 2));
		}

		/**
		 * Gets the command code from the command buffer. (TPM command code
		 * encoded in four bytes, This method returns the the two list
		 * significant bytes)
		 * 
		 * @param buffer
		 *            the buffer containing the command.
		 * @param offset
		 *            the offset in the buffer where the command starts from.
		 * 
		 * @return the command code.
		 */
		private short getCommandCode(byte[] buffer, short offset) {
			return Util.getShort(buffer, (short) (offset + OFFSET_COMMAND_CODE + 2));
		}
	}

	/**
	 * Represents an authorization session.
	 */
	private class TPM2Session {

		/**
		 * Handle of a loaded decrypt key used to encrypt salt may be
		 * TPM_RH_NULL Auth Index: None
		 */
		private short tpmKey;

		/**
		 * Entity providing the authValue may be TPM_RH_NULL Auth Index: None
		 */
		private short bindNumber;

		private byte bindType;

		/**
		 * nonce Caller, sets nonce size for the session shall be at least 16
		 * octets.
		 */
		private byte[] nonceCaller;

		/**
		 * The nonce value of the TPM
		 */
		private byte[] nonceTpm;

		/**
		 * The salt value. If session is unsalted then the salt is 00..
		 */
		private byte[] salt;

		/**
		 * The length of the salt value.
		 */
		private short lengthSalt;

		/** The session attribute **/
		private byte sessionAttribute;

		/** The session type. HMAC or policy */
		private byte sessionType;

		/** The handle for the authorization session. */
		private short authHandle;

		/**
		 * Indicates a symmetric algorithm.
		 */
		private short symmetricAlgorithm;

		/**
		 * A supported key size.
		 */
		private short symmetricKeyBits;

		/**
		 * The mode for the key.
		 */
		private short symmetricMode;

		/** The session key. */
		private byte[] sessionKey;

		/** The length of the session key. */
		private short lengthSessionKey;

		/**
		 * Hash algorithm to use for the session Shall be a hash algorithm
		 * supported by the TPM and not TPM_ALG_NULL
		 */
		private short authHash;

		/** Max nonce size the size of SHA256. */
		private static final short MAX_NONCE_SIZE = 32;

		/** Min nonce size tpm standard. */
		private static final short MIN_NONCE_SIZE = 16;

		/** The HMAC operation standard block size. */
		private final static short HMAC_BLOCK_SIZE = 64;

		/** The length of SHA-256 output. */
		private final static short LENGTH_SHA256_OUTPUT = 32;

		/** The length of SHA-1 output. */
		private final static short LENGTH_SHA1_OUTPUT = 20;

		private final static short LENGTH_AUTH_AREA_SIZE = 4;

		private final static byte LENGTH_SESSION_ATTRIBUTE = 1;

		/**
		 * Nonce size selected by the called and valid for the current session.
		 * Should be between MIN_NONCE_SIZE and MAX_NONCE_SIZE.
		 */
		private short initialNonceSize;

		/**
		 * The most recent nonce size in a session command.
		 */
		private short nonceCallerSize;

		/** Flag indicating if this session is bounded. */
		private boolean sessionIsBounded;

		/** Flag indicating if this session is salted. */
		private boolean sessionIsSalted;

		/** Message digest object for SHA 256. */
		private MessageDigest messageDigestSHA256 = null;

		/** Message digest object for SHA1. */
		private MessageDigest messageDigestSHA1 = null;

		/** Handle used to identify resources during session. */
		private short resourceHandleNumber;

		/** Transient buffer used for intermediate session operations. */
		private byte[] sessionBuffer;

		private static final short SIZE_SESSION_BUFFER = 256;
 
		/**
		 * Clears the current session after successful completion of the current
		 * command.
		 */
		private static final byte SESSION_ATTRIBUTE_CLEAR_SESSION = 0;
		private static final byte MASK_FIRST_BIT = 0x01;
 
		/**
		 * Constructor. Performs required memory initialization for session
		 * parameters.
		 */
		private TPM2Session() {
			nonceCaller = new byte[MAX_NONCE_SIZE];
			nonceTpm = new byte[MAX_NONCE_SIZE];
			sessionKey = new byte[MAX_NONCE_SIZE];
			salt = new byte[MAX_NONCE_SIZE];

			messageDigestSHA1 = MessageDigest.getInstance(MessageDigest.ALG_SHA, true);
			messageDigestSHA256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, true);

			// default session (bounded and salted)
			sessionIsBounded = true;
			sessionIsSalted = true;

			sessionBuffer = JCSystem.makeTransientByteArray(SIZE_SESSION_BUFFER, JCSystem.CLEAR_ON_DESELECT);
		}

		/**
		 * Resets session parameters. Can be performed if
		 */
		private void resetSession() {

			Util.arrayFillNonAtomic(nonceCaller, (short) 0, MAX_NONCE_SIZE, (byte) 0);
			Util.arrayFillNonAtomic(nonceTpm, (short) 0, MAX_NONCE_SIZE, (byte) 0);
			Util.arrayFillNonAtomic(sessionKey, (short) 0, MAX_NONCE_SIZE, (byte) 0);
			Util.arrayFillNonAtomic(salt, (short) 0, MAX_NONCE_SIZE, (byte) 0);
			Util.arrayFillNonAtomic(sessionBuffer, (short) 0, SIZE_SESSION_BUFFER, (byte) 0);

			sessionIsBounded = true;
			sessionIsSalted = true;

			initialNonceSize = 0;
			nonceCallerSize = 0;
			lengthSessionKey = 0;
			sessionAttribute = 0;
			resourceHandleNumber = 0;
			bindType = 0; 
			
			messageDigestSHA1.reset();
			messageDigestSHA256.reset();

		}

		/**
		 * Initializes new session parameters.
		 * 
		 * @param buffer
		 *            the buffer containing TPM_CC_StartAuthSessionCommand.
		 * @param offset
		 *            the offset in the buffer from which the command starts.
		 * @param responseBuffer
		 *            the response buffer.
		 * @param offsetResponse
		 *            the offset in response buffer to start writing from.
		 * @return length of the response.
		 */
		private short handleStartAuthSessionCommand(byte[] buffer, short offset, short length, byte[] responseBuffer, short offsetResponse) {

			short inputOffset = (short) (offset + OFFSET_HANDLE_A);

			if (TPMHandleUtil.getType(buffer, inputOffset) != TPM_HT_PERMANENT) {
				// Unsupported key handle type.
				return 0;
			}
			tpmKey = TPMHandleUtil.getNumber(buffer, inputOffset);
			inputOffset += TPM_HANDLE_SIZE;

			bindType = TPMHandleUtil.getType(buffer, inputOffset);
			bindNumber = TPMHandleUtil.getNumber(buffer, inputOffset);
			inputOffset += TPM_HANDLE_SIZE;

			// Check if session is bound to a TPM entity and/or salted.
			sessionIsSalted = tpmKey != TPM_RH_NULL;
			sessionIsBounded = bindNumber != TPM_RH_NULL;

			// Read nonce caller.
			initialNonceSize = Util.getShort(buffer, inputOffset);
			inputOffset += LENGTH_TPM2B;

			if (initialNonceSize < MIN_NONCE_SIZE || initialNonceSize > MAX_NONCE_SIZE) {
				return writeRcFmt1(responseBuffer, offsetResponse, TPM_RC_FMT1_NONCE);
			}

			// Copy nonce caller.
			Util.arrayFillNonAtomic(nonceCaller, (short) 0, MAX_NONCE_SIZE, (byte) 0);
			Util.arrayCopy(buffer, inputOffset, nonceCaller, (short) 0, initialNonceSize);
			inputOffset += initialNonceSize;

			short lengthEncryptedSalt = Util.getShort(buffer, inputOffset);
			inputOffset += LENGTH_TPM2B;

			if (sessionIsSalted) {
				lengthSalt = decryptSalt(buffer, inputOffset, lengthEncryptedSalt);

				if (lengthSalt == 0) {
					return writeRcVer1(responseBuffer, offsetResponse, TPM_RC_NORESULT);
				}
				inputOffset += lengthEncryptedSalt;
			} else {
				lengthSalt = 0;
			}

			sessionType = buffer[inputOffset];
			inputOffset += 1;

			symmetricAlgorithm = Util.getShort(buffer, inputOffset);
			inputOffset += LENGTH_TPM2B;

			if (symmetricAlgorithm != TPM_ALG_NULL) {
				symmetricKeyBits = Util.getShort(buffer, inputOffset);
				symmetricMode = Util.getShort(buffer, (short) (inputOffset + 2));
				inputOffset += 4;
			}
			authHash = Util.getShort(buffer, inputOffset);

			if (!isDigestAlgorithmSupported(authHash) || authHash == TPM_ALG_NULL) {
				return writeRcFmt1(responseBuffer, offsetResponse, TPM_RC_FMT1_HASH);
			}

			// Unbounded and unsalted session has no session key. not supported
			// currently.
			if (!sessionIsBounded && !sessionIsSalted) {
				return writeRcFmt1(responseBuffer, offsetResponse, TPM_RC_FMT1_MODE);
			}

			return getStartAuthSessionResponse(responseBuffer, offsetResponse);
		}

		/**
		 * Handles PCR operation (TPM_CC_PcrExtend, TPM_CC_PcrSetAuthValue, TPM_CC_PCR_reset).
		 * 
		 * @param buffer
		 *            the buffer containing the command
		 * @param offset
		 *            the offset in the buffer from which the command starts.
		 * @param responseBuffer
		 *            the response buffer.
		 * @param offsetResponse
		 *            the offset in response buffer to start writing from.
		 * @return length of the response.
		 */
		public short handlePcrCommand(byte[] buffer, short offset, short length, short commandCode, byte[] responseBuffer, short offsetResponse) {

			short inputOffset = (short) (offset + OFFSET_HANDLE_A);

			if (TPMHandleUtil.getType(buffer, inputOffset) != TPM_HT_PCR) {
				// invalid pcr type.
				return writeRcFmt1(responseBuffer, offsetResponse, TPM_RC_FMT1_HANDLE);
			}

			resourceHandleNumber = TPMHandleUtil.getNumber(buffer, inputOffset);
			inputOffset += TPM_HANDLE_SIZE;

			if (resourceHandleNumber == TPM_RH_NULL) {
				return writeRcSuccess(responseBuffer, offsetResponse, TPM_ST_SESSION);
			}

			short validationResult = validateAuthorizationArea(buffer, offset, length, (short) 1, responseBuffer, offsetResponse);
			if (validationResult != 0) {
				return validationResult;
			}

			// Authorization area validation
			short authAreaSize = Util.getShort(buffer, (short) (inputOffset + 2));
			inputOffset += (short) (LENGTH_AUTH_AREA_SIZE + authAreaSize);

			if (commandCode == TPM_CC_PCR_Extend) {

				short digestCount = Util.getShort(buffer, (short) (inputOffset + 2));
				inputOffset += LENGTH_DIGEST_COUNT;

				for (short i = 0; i < digestCount; i++) {
					inputOffset = extend(this.resourceHandleNumber, buffer, (short) (inputOffset + LENGTH_ALGORITHM_ID), Util.getShort(buffer, inputOffset));
				}

			} else if (commandCode == TPM_CC_PCR_SetAuthValue) {

				short authHmacLength = Util.getShort(buffer, inputOffset);
				 
				if(authHmacLength != PCR_AUTH_VALUE_LENGTH){
					return writeRcVer1(responseBuffer, offsetResponse, TPM_RC_NORESULT);
				}
				inputOffset += LENGTH_TPM2B; 
				setPCRAuthValue(resourceHandleNumber, buffer, inputOffset);

			} else if (commandCode == TPM_CC_PCR_Reset) {

				resetPcr(resourceHandleNumber);

			} else {

				return writeRcVer1(responseBuffer, offsetResponse, TPM_RC_VER1_COMMAND_CODE);

			}

			resetSessionIfRequested();
			return writeRcSuccess(responseBuffer, offsetResponse, TPM_ST_SESSION);
		}

		/**
		 * Handles TPM2 quote command.
		 * 
		 * @param buffer
		 *            the buffer containing the TPM command.
		 * @param offset
		 *            the offset in buffer from where the tpm command starts..
		 * @param length
		 *            the length of the command.
		 * @param responseBuffer
		 *            the response buffer.
		 * @param offsetResponse
		 *            the offset in responseBuffer where to start writing from.
		 * @return the length of the response.
		 */
		public short handleQuoteCommand(byte[] buffer, short offset, short length, byte[] responseBuffer, short offsetResponse) {

			short inputOffset = (short) (offset + OFFSET_HANDLE_A);

			if (!TPMHandleUtil.validateHandle(buffer, inputOffset, TPM_HT_PERMANENT, endorsementKeyPrimaryKey.getHandleNumber())) {
				// invalid signing key handle.
				return writeRcFmt1(responseBuffer, offsetResponse, TPM_RC_FMT1_HANDLE);
			}
			inputOffset += TPM_HANDLE_SIZE;

			short validationResult = validateAuthorizationArea(buffer, offset, length, (short) 1, responseBuffer, offsetResponse);
			if (validationResult != 0) {
				return validationResult;
			}

			short authSize = Util.getShort(buffer, (short) (inputOffset + 2));
			inputOffset += (short) (LENGTH_AUTH_AREA_SIZE + authSize);

			short offsetSessionBuffer = 0;
			// Build TPMS_ATTEST Structure
			offsetSessionBuffer = Util.arrayCopy(TPM_GENERATED_VALUE, (short) 0, sessionBuffer, offsetSessionBuffer, (short) TPM_GENERATED_VALUE.length);
			offsetSessionBuffer = Util.setShort(sessionBuffer, offsetSessionBuffer, TPM_ST_ATTEST_QUOTE);
			// Write the name of the signing key (handle value) in TPM2B_NAME  format.
			offsetSessionBuffer = TPMHandleUtil.writeHandle(bindType, bindNumber, sessionBuffer, offsetSessionBuffer);
			// Qualifying data format TPM2B_DATA
			short qualifyingDataLength = Util.getShort(buffer, inputOffset);
			offsetSessionBuffer = Util.arrayCopy(buffer, inputOffset, sessionBuffer, offsetSessionBuffer, (short) (LENGTH_TPM2B + qualifyingDataLength));
			inputOffset += (short) (LENGTH_TPM2B + qualifyingDataLength);

			// Write TPMS_CLOCK_INFO
			offsetSessionBuffer = Util.arrayFillNonAtomic(sessionBuffer, offsetSessionBuffer, LENGTH_EMPTY_CLOCK_VALUE, (byte) 0);
			offsetSessionBuffer = Util.setShort(sessionBuffer, offsetSessionBuffer, (short) 0);
			offsetSessionBuffer = Util.setShort(sessionBuffer, offsetSessionBuffer, tpmResetCount);
			offsetSessionBuffer = Util.setShort(sessionBuffer, offsetSessionBuffer, (short) 0);
			offsetSessionBuffer = Util.setShort(sessionBuffer, offsetSessionBuffer, tpmRestartCount);
			// Value of safe is always NO because clock is not implemented.
			sessionBuffer[offsetSessionBuffer++] = TPMI_NO;

			// Write firmware version UINT64.
			offsetSessionBuffer = Util.arrayFillNonAtomic(sessionBuffer, offsetSessionBuffer, LENGTH_FIRMWARE_VERSION, (byte) 0);
			Util.setShort(sessionBuffer, (short) (offsetSessionBuffer - 2), firmwareVersion);

			// signing scheme ... TPMT_SIG_SCHEME+ should be TPM_ALG_NULL..
			// TODO check
			inputOffset += 2;

			// TPML pcr selection structure.
			short indexPcrSelectionOffset = inputOffset;

			// Write TPMU_QOUTE_INFO
			offsetSessionBuffer = getPcrQuoteInfo(buffer, indexPcrSelectionOffset, sessionBuffer, offsetSessionBuffer);

			// TPMS_ATTEST Structure building is complete ... copy to
			// outputBuffer
			short outOffset = (short) (offsetResponse + LENGTH_TPM_RC_DEFAULT);
			short offsetParameterSize = outOffset;
			// Parameter size is written later
			outOffset += LENGTH_RESPONSE_PARAMERTER_SIZE;

			// Copy TPM2B_ATTEST (length + TPMS_ATTEST) Structure
			outOffset = Util.setShort(responseBuffer, outOffset, offsetSessionBuffer);
			outOffset = Util.arrayCopy(sessionBuffer, (short) 0, responseBuffer, outOffset, offsetSessionBuffer);

			outOffset = Util.setShort(responseBuffer, outOffset, TPM_ALG_RSASSA);

			outOffset += endorsementKeyPrimaryKey.sign(sessionBuffer, (short) 0, offsetSessionBuffer, responseBuffer, outOffset);

			// write parameter size
			short parameterSize = (short) (outOffset - offsetParameterSize - LENGTH_RESPONSE_PARAMERTER_SIZE);
			Util.setShort(responseBuffer, offsetParameterSize, (short) 0);
			Util.setShort(responseBuffer, (short) (offsetParameterSize + 2), parameterSize);

			short responseSize = (short) (LENGTH_TPM_RC_DEFAULT + LENGTH_RESPONSE_PARAMERTER_SIZE + parameterSize + LENGTH_TPM2B + initialNonceSize + LENGTH_SESSION_ATTRIBUTE);
			if (authHash == TPM_ALG_SHA256) {
				responseSize += (short) (LENGTH_TPM2B + MessageDigest.LENGTH_SHA_256);
			} else {
				responseSize += (short) (LENGTH_TPM2B + MessageDigest.LENGTH_SHA);
			}

			// Write response header
			writeRcHeader(responseBuffer, offsetResponse, TPM_ST_SESSION, responseSize, TPM_RC_SUCCESS);

			short offsetCommandCode = (short) (offset + OFFSET_COMMAND_CODE);
			short offsetResponseCode = (short) (offsetResponse + OFFSET_RESPONSE_CODE);
			short offsetParameter = (short) (offsetParameterSize + LENGTH_RESPONSE_PARAMERTER_SIZE);
			outOffset = writeResponseAuthorization(buffer, offsetCommandCode, responseBuffer, offsetResponseCode, offsetParameter, parameterSize);

			if (outOffset == 0) {
				return writeRcVer1(responseBuffer, offsetResponse, TPM_RC_NORESULT);
			}
			resetSessionIfRequested();
			return (short) (outOffset - offsetResponse);
		}

		/**
		 * Performs validation of command authorization Area.
		 * 
		 * @param buffer
		 *            the buffer containing the TPM command.
		 * @param offset
		 *            the offset in buffer from where the tpm command starts..
		 * @param length
		 *            the length of the command.
		 * @param numberOfHandles
		 *            the number of handles in the command.
		 * @param responseBuffer
		 *            the response buffer to write authorization failure
		 *            response.
		 * @param offsetResponse
		 *            the offset in responseBuffer where to start writing from.
		 * @return the length of the response.
		 * 
		 * @return 0 if the authorization area a valid and expected command Auth
		 *         HMAC, the size of the authorization failure response.
		 */
		private short validateAuthorizationArea(byte[] buffer, short offset, short length, short numberOfHandles, byte[] responseBuffer, short offsetResponse) {

			short inputOffset = (short) (offset + OFFSET_HANDLE_A + (TPM_HANDLE_SIZE * numberOfHandles));
			// Authorization area validation
			short authSize = Util.getShort(buffer, (short) (inputOffset + 2));
			inputOffset += LENGTH_AUTH_AREA_SIZE;

			// validate authorization handle. Only single session
			// TPM_HT_HMAC_SESSION_FIRST is supported.
			if (!TPMHandleUtil.validateHandle(buffer, inputOffset, TPM_HT_HMAC_SESSION, TPM_HT_HMAC_SESSION_FIRST)) {
				return writeRcFmt1(responseBuffer, offsetResponse, TPM_RC_FMT1_HANDLE);
			}
			inputOffset += TPM_HANDLE_SIZE;

			// Read TPM2B_NONCE caller.
			nonceCallerSize = Util.getShort(buffer, inputOffset);
			inputOffset += LENGTH_TPM2B;

			Util.arrayFillNonAtomic(nonceCaller, (short) 0, MAX_NONCE_SIZE, (byte) 0);
			Util.arrayCopy(buffer, inputOffset, nonceCaller, (short) 0, nonceCallerSize);
			inputOffset += nonceCallerSize;

			sessionAttribute = buffer[inputOffset];
			inputOffset += 1;

			short hmacSize = Util.getShort(buffer, inputOffset);
			short offsetAuthHmac = (short) (inputOffset + LENGTH_TPM2B);

			inputOffset += (short) (hmacSize + LENGTH_TPM2B);

			short offsetParameter = inputOffset;
			short lengthParameter = (short) (length + offset - offsetParameter);

			if (!verifyCommandHmac(buffer, (short) (offset + OFFSET_COMMAND_CODE), (short) (offset + OFFSET_HANDLE_A), (short) 1, offsetAuthHmac, offsetParameter, lengthParameter)) {
				// Increment DA counter if required
				return writeRcFmt1(responseBuffer, offsetResponse,  TPM_RC_FMT1_AUTH_FAIL);
			}
			return 0;
		}

		/**
		 * Verifies command authHmac.
		 * 
		 * @param buffer
		 *            the command buffer containing the parameters for authHmac
		 *            verification.
		 * @param offsetCommandCode
		 *            the offset of the command code.
		 * @param offsetHandles
		 *            the offset of the handles.
		 * @param numberOfHandles
		 *            the number of handles in the command.
		 * @param offsetAuthHmac
		 *            the offset of the authHmac.
		 * @param offsetParameter
		 *            the offset of the parameter.
		 * @param lengthParameter
		 *            the length of the parameter.
		 * @return true if authHmac is valid, false otherwise.
		 */
		private boolean verifyCommandHmac(byte[] buffer, short offsetCommandCode, short offsetHandles, short numberOfHandles, short offsetAuthHmac, short offsetParameter, short lengthParameter) {

			short offsetSessionBuffer = (short) (HMAC_BLOCK_SIZE * 2);
			short cpHashSize = 0;
			// compute cpHash and put it in sessionBuffer at offset
			// (HMAC_BLOCK_SIZE * 2) to ease computation of HMAC.
			// Compute cpHash = H(Command_Code || (handle Name ) || Parameters)
			if (authHash == TPM_ALG_SHA256) {
				messageDigestSHA256.update(buffer, offsetCommandCode, LENGTH_COMMAND_CODE);

				messageDigestSHA256.update(buffer, offsetHandles, (short) (numberOfHandles * TPM_HANDLE_SIZE));

				cpHashSize = messageDigestSHA256.doFinal(buffer, offsetParameter, lengthParameter, sessionBuffer, offsetSessionBuffer);

			} else if (authHash == TPM_ALG_SHA1) {

				messageDigestSHA1.update(buffer, offsetCommandCode, LENGTH_COMMAND_CODE);

				messageDigestSHA1.update(buffer, offsetHandles, (short) (numberOfHandles * TPM_HANDLE_SIZE));

				cpHashSize = messageDigestSHA1.doFinal(buffer, offsetParameter, lengthParameter, sessionBuffer, offsetSessionBuffer);

			} else {
				return false;
			}

			offsetSessionBuffer += cpHashSize;

			// Compute authHMAC HMAC sessionAlg ((sessionKey || authValue),
			// (cpHash || nonceNewer || nonceOlder || sessionAttributes))

			// copy noncenewer (nonce caller) || nonceOder(nonce TPM) ||
			// sessionAttributes to session buffer.
			offsetSessionBuffer = Util.arrayCopy(nonceCaller, (short) 0, sessionBuffer, offsetSessionBuffer, nonceCallerSize);
			offsetSessionBuffer = Util.arrayCopy(nonceTpm, (short) 0, sessionBuffer, offsetSessionBuffer, initialNonceSize);
			sessionBuffer[offsetSessionBuffer] = sessionAttribute;
			offsetSessionBuffer += 1;

			short lengthHmac = computeHmac(sessionKey, (short) 0, lengthSessionKey, (short) (offsetSessionBuffer - (short) (HMAC_BLOCK_SIZE * 2)), sessionBuffer, (short) 0);

			return Util.arrayCompare(sessionBuffer, (short) 0, buffer, offsetAuthHmac, lengthHmac) == (short) 0;
		}

		/**
		 * Computes a Response HMAC and writes to response authorization area.
		 * 
		 * @param buffer
		 *            the command buffer.
		 * @param offsetCommandCode
		 *            the offset of the command code in the command buffer.
		 * @param responseBuffer
		 *            the response buffer.
		 * @param offsetResponseCode
		 *            the offset of the response code.
		 * @param offsetParameter
		 *            the offset of the response parameter.
		 * @param lengthParameter
		 *            the length of the response parameter.
		 * @return the new offset in response buffer after writing authorization
		 *         area, 0 if computing authorization fails.
		 */
		private short writeResponseAuthorization(byte[] buffer, short offsetCommandCode, byte[] responseBuffer, short offsetResponseCode, short offsetParameter, short lengthParameter) {

			Util.arrayFillNonAtomic(sessionBuffer, (short) 0, (short) sessionBuffer.length, (byte) 0x00);
			short offsetSessionBuffer = (short) (HMAC_BLOCK_SIZE * 2);
			short rpHashSize = 0;

			// compute rpHash and put it in sessionBuffer at offset
			// HMAC_BLOCK_SIZE to ease computation of HMAC.
			// Compute rpHash = H(Response code || Command_Code || Parameters)
			if (authHash == TPM_ALG_SHA256) {

				messageDigestSHA256.update(responseBuffer, offsetResponseCode, LENGTH_RESPONSE_CODE);

				messageDigestSHA256.update(buffer, offsetCommandCode, LENGTH_COMMAND_CODE);

				rpHashSize = messageDigestSHA256.doFinal(responseBuffer, offsetParameter, lengthParameter, sessionBuffer, offsetSessionBuffer);

			} else if (authHash == TPM_ALG_SHA1) {
				messageDigestSHA1.update(responseBuffer, offsetResponseCode, LENGTH_RESPONSE_CODE);

				messageDigestSHA1.update(buffer, offsetCommandCode, LENGTH_COMMAND_CODE);

				rpHashSize = messageDigestSHA1.doFinal(responseBuffer, offsetParameter, lengthParameter, sessionBuffer, offsetSessionBuffer);

			} // NO other algorithm is supported.

			offsetSessionBuffer += rpHashSize;

			// Generate new nonce tpm and copy the value to sessionBuffer for
			// HMAC computation.
			getRandom(nonceTpm, (short) 0, initialNonceSize);

			offsetSessionBuffer = Util.arrayCopy(nonceTpm, (short) 0, sessionBuffer, offsetSessionBuffer, initialNonceSize);

			// Copy nonce caller to sessionBuffer.
			offsetSessionBuffer = Util.arrayCopy(nonceCaller, (short) 0, sessionBuffer, offsetSessionBuffer, nonceCallerSize);

			sessionBuffer[offsetSessionBuffer] = sessionAttribute;
			offsetSessionBuffer += 1;

			// Write to authorization area of response (TPM2B_NONCE_TPM ||
			// sessionAttribute || TPM2B_HMAC)

			short outOffset = (short) (offsetParameter + lengthParameter);
			outOffset = Util.setShort(responseBuffer, outOffset, initialNonceSize);
			outOffset = Util.arrayCopy(nonceTpm, (short) 0, responseBuffer, outOffset, initialNonceSize);

			responseBuffer[outOffset++] = sessionAttribute;

			if (authHash == TPM_ALG_SHA256) {
				outOffset = Util.setShort(responseBuffer, outOffset, MessageDigest.LENGTH_SHA_256);
			} else {
				outOffset = Util.setShort(responseBuffer, outOffset, MessageDigest.LENGTH_SHA_256);
			}

			short hmacSize = computeHmac(sessionKey, (short) 0, lengthSessionKey, (short) (offsetSessionBuffer - (short) (HMAC_BLOCK_SIZE * 2)), responseBuffer, outOffset);

			if (hmacSize == 0) {
				return 0;
			}
			return (short) (outOffset + hmacSize);
		}

		/**
		 * Computes HMAC assuming the input data is placed in sessionBuffer at
		 * offset (HMAC_BLOCK_SIZE * 2).
		 * 
		 * @param keyBuffer
		 *            the buffer containing the key.
		 * @param offsetKey
		 *            the offset of the key in the key buffer.
		 * @param lengthKey
		 *            the length of the key.
		 * @param dataLength
		 *            the length of the session data (should start from at
		 *            offset (HMAC_BLOCK_SIZE * 2) in sessionBuffer).
		 * @param output
		 *            the output buffer.
		 * @param offsetOutput
		 *            the offset in the output.
		 * @return the length of the HMAC if computed, 0 otherwise.
		 */
		private short computeHmac(byte[] keyBuffer, short offsetKey, short lengthKey, short dataLength, byte[] output, short offsetOutput) {

			// Compute cpHash = H(Command_Code || (handle Name ) || Parameters)
			byte hmacIpad = 0x36;
			byte hmacOpad = 0x5C;

			// offset of inner hmac block in the session buffer.
			short offset = HMAC_BLOCK_SIZE;
			for (short i = 0; i < lengthKey; i++) {
				// perform inner block xor followed by outer block key xor.
				sessionBuffer[offset] = (byte) (keyBuffer[(short) (offsetKey + i)] ^ hmacIpad);
				sessionBuffer[i] = (byte) (keyBuffer[(short) (offsetKey + i)] ^ hmacOpad);

				offset++;
			}
			Util.arrayFillNonAtomic(sessionBuffer, offset, (short) (HMAC_BLOCK_SIZE - lengthKey), hmacIpad);
			Util.arrayFillNonAtomic(sessionBuffer, lengthKey, (short) (HMAC_BLOCK_SIZE - lengthKey), hmacOpad);

			short lengthInnerHashInput = (short) (dataLength + HMAC_BLOCK_SIZE);

			if (authHash == TPM_ALG_SHA256) {
				// Inner Hash
				messageDigestSHA256.doFinal(sessionBuffer, HMAC_BLOCK_SIZE, lengthInnerHashInput, sessionBuffer, HMAC_BLOCK_SIZE);
				// Outer Hash
				return messageDigestSHA256.doFinal(sessionBuffer, (short) 0, (short) (HMAC_BLOCK_SIZE + MessageDigest.LENGTH_SHA_256), output, offsetOutput);

			} else if (authHash == TPM_ALG_SHA1) {
				// Inner Hash
				messageDigestSHA1.doFinal(sessionBuffer, HMAC_BLOCK_SIZE, lengthInnerHashInput, sessionBuffer, HMAC_BLOCK_SIZE);
				// Outer Hash
				return messageDigestSHA1.doFinal(sessionBuffer, (short) 0, (short) (HMAC_BLOCK_SIZE + MessageDigest.LENGTH_SHA), output, offsetOutput);
			}
			return 0;
		}

		/**
		 * Decrypts encrypted salted with tpmKey specified for the session.
		 * 
		 * @param inputBuffer
		 *            the input buffer containing the encrypted salt.
		 * @param inputOffset
		 *            the offset in the inputBuffer when the encrypted salt
		 *            starts from.
		 * @param length
		 *            the length of the encrypted salt.
		 * @return the length of decrypted salt value, 0 if the operation fails
		 *         fails.
		 */
		private short decryptSalt(byte[] inputBuffer, short inputOffset, short length) {
			switch (tpmKey) {
			case 0x00:
				return endorsementKeyPrimaryKey.decrypt(inputBuffer, inputOffset, length, salt, (short) 0); 
			default:
				break;
			}
			return 0;
		}

		/**
		 * Creates session parameters and Required Start Auth session response.
		 * 
		 * @param responseBuffer
		 *            the buffer to write the response to.
		 * @param offsetResponse
		 *            the offset in the response buffer to start writing from.
		 * @return the length of the response.
		 */
		private short getStartAuthSessionResponse(byte[] responseBuffer, short offsetResponse) {

			short offset = offsetResponse;

			getRandom(nonceTpm, offsetResponse, initialNonceSize); 
			
			lengthSessionKey = computeSessionKey();
			// Clear session buffer used during session key computation.
			Util.arrayFillNonAtomic(sessionBuffer, (short) 0, (short) sessionBuffer.length, (byte) 0x00);

			short responseSize;

			if (lengthSessionKey > 0) {

				responseSize = (short) (LENGTH_TAG + LENGTH_RESPONSE_SIZE + LENGTH_RESPONSE_CODE + TPM_HANDLE_SIZE + LENGTH_RESPONSE_PARAMERTER_SIZE + LENGTH_TPM2B + initialNonceSize);

				// Response header
				offset = writeRcHeader(responseBuffer, offsetResponse, TPM_ST_NO_SESSION, responseSize, TPM_RC_SUCCESS);

				// Handle Area
				offset = TPMHandleUtil.writeHandle(TPM_HT_HMAC_SESSION, TPM_HT_HMAC_SESSION_FIRST, responseBuffer, offset);

				// Parameter Area (Size + parameters)
				short parameterSize = (short) (LENGTH_TPM2B + initialNonceSize);
				offset = Util.setShort(responseBuffer, offset, (short) 0);
				offset = Util.setShort(responseBuffer, offset, parameterSize);
				offset = Util.setShort(responseBuffer, offset, initialNonceSize);
				Util.arrayCopy(nonceTpm, (short) 0, responseBuffer, offset, initialNonceSize);

			} else {
				return writeRcVer1(responseBuffer, offsetResponse, TPM_RC_NORESULT);
			}

			return responseSize;

		}

		/**
		 * Computes session key using necessary parameters from Parsed from the
		 * Start Auth session command and parameters of the TPM.
		 */
		private short computeSessionKey() {

			if (!sessionIsBounded && !sessionIsSalted) {
				// session key is empty buffer for unbounded and unsalted
				// session.
				return 0;
			}

			// Make sure the session buffer is empty.
			Util.arrayFillNonAtomic(sessionBuffer, (short) 0, (short) sessionBuffer.length, (byte) 0x00);

			short offsetSessionBuffer = 0;
			if (sessionIsBounded) {

				// Identify resource and get auth value.
				if (bindType == TPM_HT_PCR) {
					offsetSessionBuffer = getPCRAuthValue(bindNumber, sessionBuffer, offsetSessionBuffer);
				} else if (bindType == TPM_HT_PERMANENT) {
					offsetSessionBuffer = getTpmKeyAuthValue(bindNumber, sessionBuffer, offsetSessionBuffer);
				} else {
					return 0;

				}

			}

			// Copy salt value.
			if (sessionIsSalted) {
				offsetSessionBuffer = Util.arrayCopy(salt, (short) 0, sessionBuffer, offsetSessionBuffer, lengthSalt);
			}

			// hmac key = auth value || salt.
			short lengthHmacKey = offsetSessionBuffer;

			// Validate key size
			lengthHmacKey = validateHmacKeyLength(authHash, sessionBuffer, (short) 0, lengthHmacKey);
			if (lengthHmacKey == 0) {
				// Invalid key ..
				return 0;
			}

			// TODO correct comment
			// Session key generation operation. 
			// sessionKey KDFa(sessionAlg, (authValue || salt), ATH, nonceTPM, nonceCaller, bits)
			// KDFa -> K(i) = HMAC (Ki , [i] || Label || 00 || Context || [L]) 
			
			/** Since the number of bits required in the session same as the sessionAlg (authHash),
			 only the first round of KDFa is enough to generate required  number of bits for the session key. */
			short lengthKDFaData = concatSessionKDFaData((short) 1, authHash, sessionBuffer, (short) (HMAC_BLOCK_SIZE * 2));
			return computeHmac(sessionBuffer, (short) 0, lengthHmacKey, lengthKDFaData, sessionKey, (short) 0);

		}

		/**
		 * Concatenates inputs for data for the HMAC algorithm used in specific
		 * iteration.
		 * 
		 * @param counter
		 *            the current KDFa counter value.
		 * @param hashAlgorithm
		 *            the hash algorithm used in this session.
		 * @param outputBuffer
		 *            the output buffer to write KDFa data to.
		 * @param offsetOutput
		 *            the offset in the output buffer to start writing from.
		 * 
		 * @return the length of the session KDFa data.
		 */
		private short concatSessionKDFaData(short counter, short hashAlgorithm, byte[] outputBuffer, short offsetOutput) {

			short offset = offsetOutput;
			// Set 32 bit counter
			offset = Util.setShort(outputBuffer, offset, (short) 0);
			offset = Util.setShort(outputBuffer, offset, counter);

			// Copy Label-ATH, nonceTPM, nonceCaller,
			offset = Util.arrayCopy(ATH, (short) 0, outputBuffer, offset, (short) ATH.length);
			offset = Util.arrayCopy(nonceTpm, (short) 0, outputBuffer, offset, initialNonceSize);
			offset = Util.arrayCopy(nonceCaller, (short) 0, outputBuffer, offset, initialNonceSize);

			// Set 32 bit number of bits produced by the hash algorithm.
			offset = Util.setShort(outputBuffer, offset, (short) 0);
			if (hashAlgorithm == TPM_ALG_SHA256) {
				offset = Util.setShort(outputBuffer, offset, ALG_SHA256_OUTPUT_BITS_COUNT);
			} else if (hashAlgorithm == TPM_ALG_SHA1) {
				offset = Util.setShort(outputBuffer, offset, ALG_SHA1_OUTPUT_BITS_COUNT);
			} // else not supported should be handled before calling this
				// function.
			return (short) (offset - offsetOutput);
		}

		/**
		 * Validates HMAC key for the specified has algorithm and performs
		 * necessary compression if the size is larger that the allowed HMAC
		 * block size. Writes the new key in the same buffer.
		 * 
		 * @param keyBuffer
		 *            the buffer containing the key.
		 * @param keyOffset
		 *            the offset in the buffer from where the key value starts
		 *            from.
		 * @param length
		 *            the length of the key.
		 * @return the original length if the key is valid, the length of the
		 *         new key if the key is compressed, 0 if the length is invalid
		 *         or if the HMAC algorithm is not supported.
		 */
		private short validateHmacKeyLength(short hashAlgorithm, byte[] keyBuffer, short keyOffset, short length) {

			/** key length should be between length of the hash algorithm and hmac block size.
			If length of key is greater than HMAC block size it has to be hashed. */
			if (hashAlgorithm == TPM_ALG_SHA256) {

				if (length < MessageDigest.LENGTH_SHA_256) {
					return 0;
				} else if (length > HMAC_BLOCK_SIZE) {
					return messageDigestSHA256.doFinal(keyBuffer, keyOffset, length, keyBuffer, keyOffset);
				} else {
					return length;
				}

			} else if (hashAlgorithm == TPM_ALG_SHA1) {

				if (length < MessageDigest.LENGTH_SHA) {
					return 0;
				} else if (length > HMAC_BLOCK_SIZE) {
					return messageDigestSHA1.doFinal(keyBuffer, keyOffset, length, keyBuffer, keyOffset);
				} else {
					return length;
				}

			}
			return 0;
		}

		/**
		 * Extends specific bank (SHA1 or SHA256) of a PCR identified with
		 * number. Validation of pcr number and hash algorithm should be
		 * performed during command parsing.
		 * 
		 * @param pcrNumber
		 *            the PCR number.
		 * @param buffer
		 *            the buffer containing the data to extend.
		 * @param offset
		 *            the offset in buffer to start reading from.
		 * @param hashAlgorithm
		 *            the algorithm ID which identifies which PCR back to
		 *            update.
		 * @return the new offset in buffer after reading extend data or the
		 *         same offset if the hashAlgorithm is not supported.
		 */
		private short extend(short pcrNumber, byte[] buffer, short offset, short hashAlgorithm) {

			if (hashAlgorithm == TPM_ALG_SHA256) {

				short lengthPcrData = pcrList[pcrNumber].getSha256Bank(sessionBuffer, (short) 0);
				messageDigestSHA256.update(sessionBuffer, (short) 0, lengthPcrData);
				messageDigestSHA256.doFinal(buffer, offset, MessageDigest.LENGTH_SHA_256, sessionBuffer, (short) 0);
				pcrList[pcrNumber].setSha256Bank(sessionBuffer, (short) 0);
				pcrUpdateCounter++;
				return (short) (offset + MessageDigest.LENGTH_SHA_256);

			} else if (hashAlgorithm == TPM_ALG_SHA1) {

				short lengthPcrData = pcrList[pcrNumber].getSha1Bank(sessionBuffer, (short) 0);
				messageDigestSHA1.update(sessionBuffer, (short) 0, lengthPcrData);
				messageDigestSHA1.doFinal(buffer, offset, MessageDigest.LENGTH_SHA, sessionBuffer, (short) 0);
				pcrList[pcrNumber].setSha1Bank(sessionBuffer, (short) 0);
				pcrUpdateCounter++;
				return (short) (offset + MessageDigest.LENGTH_SHA);
			} else {
				// algorithm not supported. Algorithm check should be performed prior to calling extend.
				return offset;
			}
		}

		/**
		 * Gets quote info of PCR specified in the selector.
		 * 
		 * @param buffer
		 *            the buffer containing the pcr selection structure.
		 * @param offsetPcrSelection
		 *            offset in buffer where the pcr selection structure starts
		 *            from.
		 * @param outputBuffer
		 *            the output buffer to write the quote info.
		 * @param offsetOutput
		 *            offset in outputBuffer to start writing from.
		 * @return the new offset in output buffer, 0 if error occurs or if the
		 *         no PCR is selected.
		 */
		public short getPcrQuoteInfo(byte[] buffer, short offsetPcrSelection, byte[] outputBuffer, short offsetOutput) {
			short inputOffset = offsetPcrSelection;
			// Selection size
			short selectionCount = Util.getShort(buffer, (short) (inputOffset + 2));
			if (selectionCount > 1) {
				// Only one selection structure is supported due to overlapping
				// of input and output buffer.
				return 0;
			}
			inputOffset += LENGTH_PCR_SELECTION_COUNT;

			// read TPML_PCR_SELECTION structure.
			short algorithmId = Util.getShort(buffer, inputOffset);
			inputOffset += LENGTH_ALGORITHM_ID;

			if (!isDigestAlgorithmSupported(algorithmId) || algorithmId == TPM_ALG_NULL) {
				return 0;
			}

			byte sizeOfSelect = buffer[inputOffset++];

			if (sizeOfSelect < MIN_PCR_SELECT_SIZE) {
				return 0;
			}

			byte pcrSelectByte0 = buffer[inputOffset++];
			byte pcrSelectByte1 = buffer[inputOffset++];
			byte pcrSelectByte2 = buffer[inputOffset++];

			byte pcrSelectByte;
			short digestCount = 0;
			for (short i = 0; i < PLATFORM_PCR_SIZE; i++) {

				if (i / 8 == 0) {
					pcrSelectByte = pcrSelectByte0;
				} else if (i / 8 == 1) {
					pcrSelectByte = pcrSelectByte1;
				} else {
					pcrSelectByte = pcrSelectByte2;
				}
				byte pcrSelectBitNumber = (byte) (i % 8);

				// Check if the bit is set
				if ((byte) ((byte) (pcrSelectByte >> pcrSelectBitNumber) & 0x01) == 1) {
					digestCount++;
					if (algorithmId == TPM_ALG_SHA256) {
						pcrList[i].getSha256Bank(outputBuffer, offsetOutput);
						messageDigestSHA256.update(outputBuffer, offsetOutput, MessageDigest.LENGTH_SHA_256);
					} else {
						pcrList[i].getSha1Bank(outputBuffer, offsetOutput);
						messageDigestSHA1.update(outputBuffer, offsetOutput, MessageDigest.LENGTH_SHA);
					}
				}
			}

			if (digestCount == 0) {
				return 0;
			}
			short pcrSelectionLength = (short) (inputOffset - offsetPcrSelection);
			offsetOutput = Util.arrayCopy(buffer, offsetPcrSelection, outputBuffer, offsetOutput, pcrSelectionLength);

			// Do the final digest
			if (algorithmId == TPM_ALG_SHA256) {
				offsetOutput = Util.setShort(outputBuffer, offsetOutput, MessageDigest.LENGTH_SHA_256);
				offsetOutput += messageDigestSHA256.doFinal(outputBuffer, offsetOutput, (short) 0, outputBuffer, offsetOutput);

			} else {
				offsetOutput = Util.setShort(outputBuffer, offsetOutput, MessageDigest.LENGTH_SHA);
				offsetOutput += messageDigestSHA1.doFinal(outputBuffer, offsetOutput, (short) 0, outputBuffer, offsetOutput);
			}
			resetSessionIfRequested();
			return offsetOutput;
		}
		
		/**
		 * Checks the current attribute and resets the session if reset is requested.
		 */
		private void  resetSessionIfRequested(){
			if((byte)(sessionAttribute & MASK_FIRST_BIT) == SESSION_ATTRIBUTE_CLEAR_SESSION){
				resetSession();
			}
		}

	}

	/**
	 * Checks if the hash algorithm is supported. (TPM_ALG_NULL is considered as valid).
	 * 
	 * @param algorithmId
	 *            the algorithm id.
	 * @return true if valid and supported false otherwise.
	 */
	private boolean isDigestAlgorithmSupported(short algorithmId) {
		switch (algorithmId) {
			
		case TPM_ALG_SHA256:
			case TPM_ALG_SHA1:
			case TPM_ALG_NULL:
				return true;
			
			default:
				return false;
		} 
	}

	/**
	 * Gets the auth value of the PCRs used in this implementation.
	 * 
	 * @param pcrNumber
	 *            the PCR number (The two list significant bytes of the PCR
	 *            handle).
	 * @param outputBuffer
	 *            the output buffer to write the PCR value to.
	 * @param offset
	 *            the offset in the output buffer to start writing from.
	 * @return the new offset in the outputBuffer.
	 */
	private short getPCRAuthValue(short pcrNumber, byte[] outputBuffer, short offset) {

		if (pcrNumber >= 0 && pcrNumber <= 24) {
			return Util.arrayCopy(PCR_PROTECTION_GROUP_01_AUTH, (short) 0, outputBuffer, offset, PCR_AUTH_VALUE_LENGTH);
		}
		return offset;
	}

	/**
	 * Set a PCR auth value.
	 * 
	 * @param pcrNumber
	 *            the PCR number (The two list significant bytes of the PCR
	 *            handle).
	 * @param buffer
	 *            the buffer containing the new Auth value.
	 * @param offset
	 *            the offset in buffer to start reading from.
	 * @return the offset in buffer after reading the PCR auth value.
	 */
	private short setPCRAuthValue(short pcrNumber, byte[] buffer, short offset) {
		if (pcrNumber >= 0 && pcrNumber <= PLATFORM_PCR_SIZE) {
			Util.arrayCopy(buffer, offset, PCR_PROTECTION_GROUP_01_AUTH, (short) 0, PCR_AUTH_VALUE_LENGTH);
			return (short) (offset + PCR_AUTH_VALUE_LENGTH);
		}
		return offset;
	}

	/**
	 * Resets digest values of specific PCR.
	 * 
	 * @param pcrNumber
	 *            the PCR number (The two list significant bytes of the PCR
	 *            handle).
	 */
	private void resetPcr(short pcrNumber) {
		if (pcrNumber >= 0 && pcrNumber <= PLATFORM_PCR_SIZE) {
			pcrList[pcrNumber].reset();
		}
	}

	/**
	 * Gets the auth value of the PCRs used in this implementation.
	 * 
	 * @param pcrNumber
	 *            the PCR number (The two list significant bytes of the PCR
	 *            handle).
	 * @param outputBuffer
	 *            the output buffer to write the PCR value to.
	 * @param offset
	 *            the offset in the output buffer to start writing from.
	 * @return the new offset in the outputBuffer.
	 */
	private short getTpmKeyAuthValue(short handleNumber, byte[] outputBuffer, short offset) {

		switch (handleNumber) {
		case 0x01:
			return endorsementKeyPrimaryKey.getAuthValue(outputBuffer, offset);
		default:
			return offset;
		}
	}

	/**
	 * Gets PCR values specified in PCR selection structure.
	 * 
	 * @param buffer
	 *            the buffer containing the TPM command.
	 * @param offset
	 *            the offset in buffer from where the tpm command starts..
	 * @param length
	 *            the length of the command.
	 * @param responseBuffer
	 *            the response buffer.
	 * @param offsetResponse
	 *            the offset in responseBuffer where to start writing from.
	 * @return the length of the response.
	 */
	public short handlePcrReadCommand(byte[] buffer, short offset, short length, byte[] responseBuffer, short offsetResponse) {

		// Parameter starts after command codes (no handles or authorization is required.)
		short inputOffset = (short) (offset + LENGTH_DEFAULT_COMMAND_HEADER);

		// Selection size
		short selectionCount = Util.getShort(buffer, (short) (inputOffset + 2));
		if (selectionCount > 1) {
			// Only one selection structure is supported due to overlapping of
			// input and output buffer.
			return writeRcVer1(responseBuffer, offsetResponse, TPM_RC_NORESULT);
		}
		inputOffset += LENGTH_PCR_SELECTION_COUNT;

		// read TPML_PCR_SELECTION structure.
		short algorithmId = Util.getShort(buffer, inputOffset);
		inputOffset += LENGTH_ALGORITHM_ID;

		// TODO check supported hash algorithm.

		byte sizeOfSelect = buffer[inputOffset++];

		if (sizeOfSelect < MIN_PCR_SELECT_SIZE) {
			return writeRcVer1(responseBuffer, offsetResponse, TPM_RC_NORESULT);
		}

		// Get list of pcrSelectBytes before starting to write response b/c
		// input and output buffer could overlap
		byte pcrSelectByte0 = buffer[inputOffset++];
		byte pcrSelectByte1 = buffer[inputOffset++];
		byte pcrSelectByte2 = buffer[inputOffset++];

		// Start writing response
		short outOffset = (short) (offsetResponse + LENGTH_TPM_RC_DEFAULT);

		// Parameter size is written later
		short offsetParameterSize = outOffset;
		outOffset += LENGTH_RESPONSE_PARAMERTER_SIZE;

		// write pcr update counter
		outOffset = Util.setShort(responseBuffer, outOffset, (short) 0);
		outOffset = Util.setShort(responseBuffer, outOffset, pcrUpdateCounter);

		// Write selection structure counter.
		outOffset = Util.setShort(responseBuffer, outOffset, (short) 0);
		outOffset = Util.setShort(responseBuffer, outOffset, selectionCount);

		responseBuffer[outOffset++] = sizeOfSelect;
		short offsetPcrSelectionOut = outOffset;

		outOffset = Util.arrayFillNonAtomic(responseBuffer, offsetPcrSelectionOut, sizeOfSelect, (byte) 0);

		// Read pcrSelectionIn and Write TPML_DIGEST structure. (Digest count ||
		// TPM2B_DIGEST).
		// digest count is written later b/c its dependent on the pcrSelectionIn
		// and the capacity of response buffer
		short digestCount = 0;
		short offsetDigestCount = outOffset;
		outOffset += LENGTH_DIGEST_COUNT;

		byte pcrSelectByte;
		for (short i = 0; i < PLATFORM_PCR_SIZE; i++) {

			if (i / 8 == 0) {
				pcrSelectByte = pcrSelectByte0;
			} else if (i / 8 == 1) {
				pcrSelectByte = pcrSelectByte1;
			} else {
				pcrSelectByte = pcrSelectByte2;
			}

			byte pcrSelectBitNumber = (byte) (i % 8);

			// Check if the pit is set
			if ((byte) ((byte) (pcrSelectByte >> pcrSelectBitNumber) & 0x01) == 1) {

				digestCount += 1;

				if (algorithmId == TPM_ALG_SHA256) {
					if ((short) (outOffset + MessageDigest.LENGTH_SHA_256) > responseBuffer.length) {
						break;
					}
					// write TPM2B_DIGEST digest (length || digest value)
					outOffset = Util.setShort(responseBuffer, outOffset, MessageDigest.LENGTH_SHA_256);
					outOffset = pcrList[i].getSha256Bank(responseBuffer, outOffset);
				} else {
					if ((short) (outOffset + MessageDigest.LENGTH_SHA) > responseBuffer.length) {
						break;
					}
					outOffset = Util.setShort(responseBuffer, outOffset, MessageDigest.LENGTH_SHA);
					outOffset = pcrList[i].getSha1Bank(responseBuffer, outOffset);
				}

				// Set the pcrSelectionOut
				short offsetCurrentPcrSelectionByte = (short) (offsetPcrSelectionOut + (short) (i / 8));
				responseBuffer[offsetCurrentPcrSelectionByte] = (byte) (responseBuffer[offsetCurrentPcrSelectionByte] | (byte) (0x01 << pcrSelectBitNumber));
			}
		}

		if (digestCount > 0) {
			// Write parameter size
			Util.setShort(responseBuffer, offsetParameterSize, (short) 0);
			Util.setShort(responseBuffer, (short) (offsetParameterSize + 2), (short) (outOffset - LENGTH_TPM_RC_DEFAULT - offsetResponse));

			// Write digest count
			offsetDigestCount = Util.setShort(responseBuffer, offsetDigestCount, (short) 0);
			Util.setShort(responseBuffer, offsetDigestCount, digestCount);

			// Write response header
			short responseSize = (short) (outOffset - offsetResponse);
			writeRcHeader(responseBuffer, offsetResponse, TPM_ST_NO_SESSION, responseSize, TPM_RC_SUCCESS);
			return responseSize;
		} else {
			return writeRcSuccess(responseBuffer, offsetResponse, TPM_ST_NO_SESSION);
		}
	}

	/**
	 * Gets public key certificate of RSA keys.
	 * 
	 * @param buffer
	 *            the buffer containing the TPM command.
	 * @param offset
	 *            the offset in buffer from where the tpm command starts..
	 * @param length
	 *            the length of the command.
	 * @param responseBuffer
	 *            the response buffer.
	 * @param offsetResponse
	 *            the offset in responseBuffer where to start writing from.
	 * @return the length of the response.
	 */
	public short handleReadPublicCommand(byte[] buffer, short offset, short length, byte[] responseBuffer, short offsetResponse) {

		short inputOffset = (short) (offset + LENGTH_DEFAULT_COMMAND_HEADER);

		short handleType = TPMHandleUtil.getType(buffer, inputOffset);
		short handleNumber = TPMHandleUtil.getNumber(buffer, inputOffset);

		short outOffset = (short) (offsetResponse + LENGTH_TPM_RC_DEFAULT);

		short offsetParameterSize = outOffset;
		outOffset += LENGTH_RESPONSE_PARAMERTER_SIZE;
		short offsetParameter = outOffset;

		if (handleType == TPM_HT_PERMANENT) {
			if (handleNumber == endorsementKeyPrimaryKey.getHandleNumber()) {
				outOffset = Util.setShort(responseBuffer, outOffset, endorsementKeyPrimaryKey.getKeySize());
				if(endorsementKeyPrimaryKey.hasCertificate()){ 
					outOffset = endorsementKeyPrimaryKey.getPublicKeyCertificate(responseBuffer, outOffset);
				}else{
					outOffset = endorsementKeyPrimaryKey.getPublicKey(responseBuffer, outOffset);
				}
				// Write the name (handle)
				outOffset = Util.setShort(responseBuffer, outOffset, TPM_HANDLE_SIZE);
				outOffset = TPMHandleUtil.writeHandle(TPM_HT_PERMANENT, (short) 1, responseBuffer, outOffset);
			} else {
				return writeRcFmt1(responseBuffer, offsetResponse, TPM_RC_FMT1_HANDLE);
			}
		} else {
			return writeRcFmt1(responseBuffer, offsetResponse, TPM_RC_FMT1_HANDLE);
		}

		short parameterSize = (short) (outOffset - offsetParameter);
		Util.setShort(responseBuffer, offsetParameterSize, (short) 0);
		Util.setShort(responseBuffer, (short) (offsetParameterSize + 2), parameterSize);
		short responseSize = (short) (outOffset - offsetResponse);

		writeRcHeader(responseBuffer, offsetResponse, TPM_ST_NO_SESSION, responseSize, TPM_RC_SUCCESS);

		return responseSize;
	}
	
	/**
	 * Stores the public key certificate of the endorsement key. 
	 * (This is not standard TPM command and can only be called before startup).
	 * It used for setting up the endorsement key certificate created by an external entity. 
	 * Because the the RSA keys used in this implementation are created by the applet during installation, signing the signature will require to read the public part of the key and storing the corresponding signature.) 
	 * 
	 * @param buffer
	 *            the buffer containing the command.
	 * @param offset
	 *            the offset in buffer from where the command starts..
	 * @param length
	 *            the length of the command.
	 * @param responseBuffer
	 *            the response buffer.
	 * @param offsetResponse
	 *            the offset in responseBuffer where to start writing from.
	 * @return the length of the response.
	 * */
	private short storeEndorsementPublicKeyCertificate(byte[] buffer, short offset, short length, byte[] responseBuffer, short offsetResponse){
		endorsementKeyPrimaryKey.setPublicKeyCertificate(buffer, offset, length);
		return writeRcSuccess(responseBuffer, offsetResponse, TPM_ST_NO_SESSION);
	}
	
	/** 
	 * Gets the public part of the endorsement key to be signed externally. (This is not standard TPM command and can only be called before startup).
	 *
	 * @param responseBuffer
	 *			  the response buffer.
	 * @param offsetResponse
	 *            the offset in responseBuffer where to start writing from.
	 * @return the length of the response.
	 */
	private short getEndorsementPublicKey(byte[] responseBuffer, short offsetResponse){
		return endorsementKeyPrimaryKey.getPublicKey(responseBuffer, offsetResponse);
	}
	
	/**
	 * Process TPM2_CC_GetRandom command.
	 * 
	 * @param buffer
	 *            the buffer containing the TPM command.
	 * @param offset
	 *            the offset in buffer from where the tpm command starts..
	 * @param length
	 *            the length of the command.
	 * @param responseBuffer
	 *            the response buffer.
	 * @param offsetResponse
	 *            the offset in responseBuffer where to start writing from.
	 * @return the length of the response.
	 */
	public short handleGetRandomCommand(byte[] buffer, short offset, short length, byte[] responseBuffer, short offsetResponse){
		
		short inputOffset = (short) (offset + LENGTH_DEFAULT_COMMAND_HEADER);

		short randomBytesToSend = Util.getShort(buffer, inputOffset);
		
		/** The number of random bytes returned should not be greater than the maximum digest size implemented. */
		if(randomBytesToSend > ALT_SHA256_OUTPUT_BYTES_COUNT){
			randomBytesToSend = ALT_SHA256_OUTPUT_BYTES_COUNT; 
		}
		short outOffset = (short) (offsetResponse + LENGTH_TPM_RC_DEFAULT);
	
		//Write parameter size
		short parameterSize = (short)(LENGTH_TPM2B + randomBytesToSend);
		outOffset = Util.setShort(responseBuffer, outOffset, (short)0);
		outOffset = Util.setShort(responseBuffer, outOffset, parameterSize);
		
		// Write random bytes in TPM2B_DIGEST format
		outOffset = Util.setShort(responseBuffer, outOffset, randomBytesToSend);
		outOffset = getRandom(responseBuffer, offsetResponse, randomBytesToSend);
	 
		short responseSize = (short) (outOffset - offsetResponse);
		writeRcHeader(responseBuffer, offsetResponse, TPM_ST_NO_SESSION, responseSize, TPM_RC_SUCCESS);
		return responseSize;
	}

	/**
	 * Processes TPM2_Shutdown command.
	 * 
	 * @param buffer
	 *            the buffer containing the TPM command.
	 * @param offset
	 *            the offset tpm command starts from.
	 * @param length
	 *            the length of the command.
	 * @param responseBuffer
	 *            the response buffer.
	 * @param offsetResponse
	 *            the offset in response buffer to start writing from.
	 * @return the length of the response.
	 */
	private short handleShutdownCommand(byte[] buffer, short offset, short length, byte[] responseBuffer, short offsetResponse) {
		short parameterOffset = (short) (offset + LENGTH_DEFAULT_COMMAND_HEADER);
		// No handle or authorization is required. Parmeter follows the command
		// code.
		this.tpm_su = Util.getShort(buffer, parameterOffset);
		startupCommandExpected = true;
		return writeRcSuccess(responseBuffer, offsetResponse, TPM_ST_NO_SESSION);
	}

	/**
	 * Processes TPM2_startup command.
	 * 
	 * @param buffer
	 *            the buffer containing the TPM command.
	 * @param offset
	 *            the offset tpm command starts from.
	 * @param length
	 *            the length of the command.
	 * @param responseBuffer
	 *            the response buffer.
	 * @param offsetResponse
	 *            the offset in response buffer to start writing from.
	 * @return the length of the response.
	 */
	private short handleStartupCommand(byte[] buffer, short offset, short length, byte[] responseBuffer, short offsetResponse) {

		short parameterOffset = (short) (offset + LENGTH_DEFAULT_COMMAND_HEADER);
		short startUpType = Util.getShort(buffer, parameterOffset);

		if (startUpType == TPM_SU_CLEAR && this.tpm_su == TPM_SU_CLEAR) {
			// TPM reset
			tpmReset();
		} else if (startUpType == TPM_SU_CLEAR && this.tpm_su == TPM_SU_STATE) {
			// TPM restart
			tpmRestart();
		} else if (startUpType == TPM_SU_STATE && this.tpm_su == TPM_SU_STATE) {
			// TPM resume
			tpmResume();
		} else {
			// invalid state
			return writeRcFmt1(responseBuffer, offsetResponse, TPM_RC_FMT1_VALUE);
		}

		startupCommandExpected = false;
		return writeRcSuccess(responseBuffer, offsetResponse, TPM_ST_NO_SESSION);

	}

	/**
	 * Performs TPM reset.
	 */
	private void tpmReset() {
		tpmResetCount++;
		tpmRestartCount = 0;
		tpm2Session.resetSession();
		resetPlaformPcrs();
	}

	private void tpmRestart() {
		tpmRestartCount++;
		tpm2Session.resetSession();
		resetPlaformPcrs();
	}

	/**
	 * Resets all PCRs and PCR update counter.
	 */
	private void resetPlaformPcrs() {
		for (short i = 0; i < PLATFORM_PCR_SIZE; i++) {
			resetPcr(i);
		}
		pcrUpdateCounter = 0;
	}

	private void tpmResume() {
		tpmRestartCount++;
	}

	/**
	 * Gets random bytes of the specified size.
	 * 
	 * @param outputBuffer
	 *            the output buffer to hold the random bytes.
	 * @param offset
	 *            the offset in the output.
	 * @param size
	 *            the required size of the random data.
	 * @return the new offset in the output buffer.
	 */
	private short getRandom(byte[] outputBuffer, short offset, short size) {
		try { 
			randomData.generateData(outputBuffer, offset, size); 
			return (short) (offset + size);
		} catch (CryptoException e) {
			return offset;
		}
	}

}
