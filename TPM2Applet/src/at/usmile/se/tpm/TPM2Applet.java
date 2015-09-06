/**
 * 
 */
package at.usmile.se.tpm;



import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.ISO7816;
import javacard.framework.APDU;
import javacard.framework.Util;
import javacardx.apdu.ExtendedLength;

 
/**
 * 
 * TPM2 Applet class.
 * 
 * @author endalkachew.asnake
 *
 */
public class TPM2Applet extends Applet implements ExtendedLength{
	
	 
	private TPM tpm;
	
	/** Extended buffer for processing command and responses. */
	byte[] extendedBuffer;
	
	private final static short 	EXTENDED_APDU_BUFFER_SIZE = 1024;
	
	/** A command code for all commands that should be processed by the TPM implementation. */
	private static final byte TPM_APDU_COMMAND_CODE = 0x00;
	
	
	private TPM2Applet(){
		tpm = new TPM();
		extendedBuffer = new byte[EXTENDED_APDU_BUFFER_SIZE];
		register();
	}
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		 new TPM2Applet().register(bArray, (short) (bOffset + 1),bArray[bOffset]);
	}

	public void process(APDU apdu) { 
		if (selectingApplet()) {
			tpm.initTpm();
			return;
		}
		short lengthResponse = 0;

		
		byte[] buffer = apdu.getBuffer();
		switch (buffer[ISO7816.OFFSET_INS]) {
		
			case (byte) TPM_APDU_COMMAND_CODE:		
				short receivedLen = apdu.setIncomingAndReceive();
				short totalLength = apdu.getIncomingLength();
		 
				short incomingOffset = (short)0; 
				Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, extendedBuffer, incomingOffset, receivedLen); 
				while(receivedLen > (short)0){
					incomingOffset += receivedLen;
					receivedLen = apdu.receiveBytes((short)0);
					Util.arrayCopyNonAtomic(buffer, (short)0, extendedBuffer, incomingOffset, receivedLen); 
				}
				lengthResponse = tpm.processCommand(extendedBuffer, (short)0, totalLength, extendedBuffer, (short)0);			
				sendData(apdu, lengthResponse);			
				break;
				  
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	
	private void sendData(APDU apdu, short length) {
	    byte[] buffer = apdu.getBuffer(); 
	    short le = apdu.setOutgoing();
	    if(le != length){ 
	    	apdu.setOutgoingLength(length);
	    }
	    short offsetExtendedBuffer = 0;
	    short currentLength = le;
	    while(length > 0){
	    	if(length < le){ 
	    	   currentLength = length;
	    	}
	    	Util.arrayCopy(extendedBuffer, offsetExtendedBuffer, buffer, (short)0, currentLength);
	    	offsetExtendedBuffer += currentLength;
	    	apdu.sendBytes((short)0, currentLength);
	    	length -= currentLength;
	    } 
	}
	
}