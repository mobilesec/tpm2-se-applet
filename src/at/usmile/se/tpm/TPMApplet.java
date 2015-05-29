package at.usmile.se.tpm;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.RandomData;

/**
 * JavaCard applet implementing TPM 2.0 functionality
 * 
 * AIDs: 
 * Package = |TPMApplet
 * Applet = |TPMApplet
 * 
 * @author Michael Hölzl
 * @version 0.1
 */
public class TPMApplet extends Applet {
	
	private final byte CLA_ISO    = (byte) 0x00;		// ISO 7816 commands
	
	// CONSTANT VALUES
	// APDU max size as constant 
	private static final byte MAX_APDU_SIZE = (byte) 0xff;

	// TPM Header and data sizes
	private static final byte TPM_CC_HEADER_LENGTH = 7;
	private static final byte TPM_RC_HEADER_LENGTH = 5;
	private static final byte TPM_MAX_CC_DATA_SIZE = (MAX_APDU_SIZE - TPM_CC_HEADER_LENGTH) ;
	private static final byte TPM_MAX_RC_DATA_SIZE = (MAX_APDU_SIZE - TPM_RC_HEADER_LENGTH) ;

	private final byte[] TPM_ST_NO_SESSIONS					= { (byte) 0x80, (byte) 0x01 };

	private final byte INS_PCR_GetRandom				= (byte) 0x7B;
	private final byte INS_NV_Write								=  (byte) 0x37;

	private final byte[] INS_TPM_CC_NV_ReadPublic					= { (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x69 };
	private final byte INS_NV_ReadPublic						=  (byte) 0x69;
	
	// TPM Response codes 
	private final byte[] TPM_RC_SUCCESS							= { (byte) 0x00, (byte) 0x00 };
	private final byte[] TPM_RC_BAD_TAG							= { (byte) 0x00, (byte) 0x1E };

	private final byte[] TPM_RC_FAILURE							= { (byte) 0x1, (byte) 0x01 };
	private final byte[] TPM_RC_NV_SPACE						= { (byte) 0x1, (byte) 0x4B };
	private final byte[] TPM_RC_NV_UNAVAILABLE					= { (byte) 0x9, (byte) 0x23 };
	
	private final byte[] TPM_RC_VALUE							= { (byte) 0x0, (byte) 0x04 };
		
	byte[] TPM_DEFAULT_RC												= { (byte) 0x00, (byte) 0x00 };

	// TODO initialize PCRs

	// TPM NV data store
	private static TPM_NV_Data [] mNV_Data;
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new at.usmile.se.tpm.TPMApplet().register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
	}

	public void deselect() {
		super.deselect();
	}
	
	public TPMApplet() {
		
		// TODO initialize MAC algorithms for PCR
		
		// Initialize TPM NV Data
		mNV_Data  = new TPM_NV_Data[(short)32];
		for (short i=0;i<mNV_Data.length;i++) {
			mNV_Data[i]= new TPM_NV_Data();
		}
	}
		
	public void process(APDU apdu) {
		
		// get the APDU buffer byte array
		byte[] buf = apdu.getBuffer();
		
        if (this.selectingApplet()){
        	// Good practice: Return 9000 on SELECT
            return;
        }
        
   		byte   CLA = buf[ISO7816.OFFSET_CLA];
		byte   INS = buf[ISO7816.OFFSET_INS];
		byte   P1  = buf[ISO7816.OFFSET_P1];
		byte   P2  = buf[ISO7816.OFFSET_P2];
		
		short Lr = apdu.setIncomingAndReceive();
		
		short Lc = apdu.getIncomingLength();
		
		short dataOffset = apdu.getOffsetCdata();
		
		short Lo = 2;
		short Le = 0;
		
		// check whether the C_APDU length is valid
		if (Lr != Lc) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
	
		// Verify that we support the command before executing it
		validateTPMCommand(apdu, Lc, Le, Lo, Lr, buf, dataOffset);
		
		switch ( CLA & (byte) 0xC0) { 

			case CLA_ISO:
				
				switch (INS) {


					case INS_PCR_GetRandom:
						// Instruction code
						TPMCCGetRandom(apdu, Lc, Le, Lo, Lr, buf, dataOffset);
						break;
						
					case INS_NV_ReadPublic:
						//Read public area of NV
						TPMCCNVReadPublic(apdu, Lc, Le, Lo, Lr, buf, dataOffset);
						break;

					case INS_NV_Write:
						//Write NV data
						TPMCCNVWrite(apdu, Lc, Le, Lo, Lr, buf, dataOffset);
						break;
						
					default:
						// good practice: If you don't know the INStruction, say so:
						ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
				
				}  
				break;
				
			default:
				ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		} 	
	}

	private void validateTPMCommand(APDU apdu, short Lc, short Le, short Lo, short Lr, byte[] buf, short dataOffset) {
		// TODO verify that the Command is supported
	}

	private void TPMCCStartup(APDU apdu, short Lc, short Le, short Lo, short Lr, byte[] buf, short dataOffset) {
		
	}

	private void TPMCCStartAuthenticationSession(APDU apdu, short Lc, short Le, short Lo, short Lr, byte[] buf, short dataOffset) {
		// TODO Start authenticated session
	}

	private void TPMCCPCRExtended(APDU apdu, short Lc, short Le, short Lo, short Lr, byte[] buf, short dataOffset) {
		// TODO Add Hash to the last computed hash and comput new one (only if authenticated)
	}

	private void TPMCCPCRRead(APDU apdu, short Lc, short Le, short Lo, short Lr, byte[] buf, short dataOffset) {
		// TODO Return PCR with the given number
	}

	private void TPMCCPCRReset(APDU apdu, short Lc, short Le, short Lo, short Lr, byte[] buf, short dataOffset) {
		// TODO Reset the PCR (only if authenticated)
	}

	private void TPMCCGetRandom(APDU apdu, short Lc, short Le, short Lo, short Lr, byte[] buf, short dataOffset) {
		
		short randomLength;
		
		// Assemble response
		// Tag
		Util.arrayCopyNonAtomic(TPM_ST_NO_SESSIONS, (short) 0, buf, (short) 0, (short) 2);
		
		randomLength = Util.getShort(buf, (short) (dataOffset+(TPM_CC_HEADER_LENGTH&0xff)));
		
		if(randomLength > (TPM_MAX_RC_DATA_SIZE&0xff)){
			randomLength = TPM_MAX_RC_DATA_SIZE&0xff;
		}
		
		// Size
		Lo = (short) (TPM_RC_HEADER_LENGTH+randomLength);
		buf[2] = (byte) Lo;
		
		buf[TPM_RC_HEADER_LENGTH] = (byte) (TPM_RC_HEADER_LENGTH+randomLength&0xff);

		try{
			RandomData.getInstance(RandomData.ALG_SECURE_RANDOM).generateData(buf, TPM_RC_HEADER_LENGTH, randomLength);
		} catch(CryptoException e){
			Util.arrayCopyNonAtomic(TPM_RC_FAILURE, (short) 0, TPM_DEFAULT_RC, (short) 0, (short) 2);
		}

		// Response code
		Util.arrayCopyNonAtomic(TPM_DEFAULT_RC, (short) 0, buf, (short) 3, (short) 2);
		// Check length
		Le = apdu.setOutgoing();
		if ( Le < Lo ) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		// Send response
        apdu.setOutgoingLength(Lo);
		apdu.sendBytes((short)0, Lo);
		
	}

	/**
	 * Returns the data entry with the given index. If the index does not exist, 
	 * it returns the last empty index in the data store. When there is no entry left
	 * it returns null; 
	 * 
	 * @param persistentIndex
	 * @return
	 */
	private TPM_NV_Data getDataFromIndex(short persistentIndex, boolean getEmptyEntry){
		TPM_NV_Data lastEmptyData = null;
		for (TPM_NV_Data data : mNV_Data) {
			if(data==null) continue;
			
			if(data.getIndex() == persistentIndex){
				return data;
			} else if(getEmptyEntry && data.getIndex() == 0){
				lastEmptyData = data;
			}
		}
		return lastEmptyData;
	}

	private TPM_NV_Data deleteDataFromIndex(short index){
		for (TPM_NV_Data data : mNV_Data) {
			if(data.getIndex() == index){
				data.setIndex((short) 0);
				data.setDataEntry(null);
			}
		}
		return null;
	}
	private void TPMCCNVWrite(APDU apdu, short Lc, short Le, short Lo, short Lr, byte[] buf, short dataOffset) {
		
		short index =0;
		short dataLength = 0;
		// Assemble response
		// Tag
		Util.arrayCopyNonAtomic(TPM_ST_NO_SESSIONS, (short) 0, buf, (short) 0, (short) 2);

		if(Lc >= TPM_CC_HEADER_LENGTH + 14){
			index = (short)Utils.byteArrayToInt(buf, (short)(dataOffset + TPM_CC_HEADER_LENGTH+10), (short)2);
			dataLength = (short)Utils.byteArrayToInt(buf, (short)(dataOffset + TPM_CC_HEADER_LENGTH+12), (short)2);
			
			TPM_NV_Data dataEntry = getDataFromIndex(index, true);
			if(dataEntry != null){
				dataEntry.setDataEntry(buf, (short)(dataOffset + TPM_CC_HEADER_LENGTH+14), dataLength);
				dataEntry.setSize(dataLength);
				dataEntry.setIndex(index);
			} else{
				Util.arrayCopyNonAtomic(TPM_RC_NV_SPACE, (short) 0, TPM_DEFAULT_RC, (short) 0, (short) 2);				
			}
		} else{
			// update response code
			Util.arrayCopyNonAtomic(TPM_RC_VALUE, (short) 0, TPM_DEFAULT_RC, (short) 0, (short) 2);
		}
		
		// Response code
		Util.arrayCopyNonAtomic(TPM_DEFAULT_RC, (short) 0, buf, (short) 3, (short) 2);		
		
		Lo = (short) (TPM_RC_HEADER_LENGTH); 
		
		// Size
		buf[2] = (byte) Lo;		
		// Check length
		Le = apdu.setOutgoing();
		if ( Le < Lo ) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		// Send response
        apdu.setOutgoingLength(Lo);
		apdu.sendBytes((short)0, Lo);
		
	}

	private void TPMCCNVReadPublic(APDU apdu, short Lc, short Le, short Lo, short Lr, byte[] buf, short dataOffset) {
		
		short persistentIndex =0;
		short dataLength = 0;
		// Assemble response
		// Tag
		Util.arrayCopyNonAtomic(TPM_ST_NO_SESSIONS, (short) 0, buf, (short) 0, (short) 2);
		

		if(Lc >= TPM_CC_HEADER_LENGTH + 4){
			persistentIndex = (short)Utils.byteArrayToInt(buf, (short)(dataOffset + TPM_CC_HEADER_LENGTH+2), (short)2);
			
			TPM_NV_Data data = getDataFromIndex(persistentIndex, false);
			if(data !=null){
				dataLength = (short) (data.getSize()); 
				Util.arrayCopyNonAtomic(data.getDataEntry(), (short) 0, buf, (short) (TPM_RC_HEADER_LENGTH), dataLength);
			} else{
				Util.arrayCopyNonAtomic(TPM_RC_NV_UNAVAILABLE, (short) 0, TPM_DEFAULT_RC, (short) 0, (short) 2);				
			}
		} else{
			// update response code
			Util.arrayCopyNonAtomic(TPM_RC_VALUE, (short) 0, TPM_DEFAULT_RC, (short) 0, (short) 2);
		}
		
		// Response code
		Util.arrayCopyNonAtomic(TPM_DEFAULT_RC, (short) 0, buf, (short) 3, (short) 2);		
		
		Lo = (short) (TPM_RC_HEADER_LENGTH + dataLength); 
		
		// Size
		buf[2] = (byte) Lo;		
		// Check length
		Le = apdu.setOutgoing();
		if ( Le < Lo ) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		// Send response
        apdu.setOutgoingLength(Lo);
		apdu.sendBytes((short)0, Lo);
		
	}
}
