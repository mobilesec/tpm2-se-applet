 
package at.usmile.se.tpm;
 
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.ISO7816;
import javacard.framework.APDU;
import javacard.framework.Util; 

 
/**
 * 
 * TPM2 Applet class.
 * 
 * Copyright 2016 - 2017
 *
 * Endalkachew Asnake <endalkachew.asnake@usmile.at>
 * Michael Hölzl <hoelzl@ins.jku.at>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

public class TPM2Applet extends Applet {
	
	 
	/** The TPM implementation. */
	private TPM tpm;
	
	/** Extended buffer for processing command and responses. */
	byte[] extendedBuffer;
	
	private final static short 	EXTENDED_APDU_BUFFER_SIZE = 1024;
	
	/** 
	 * Instruction code to get remaining data from extended buffer.
	 * Send 8001000000 to get any remaining data from extended buffer.
	 * */
	private final static byte EXTENDED_BUFFER_GET_DATA = 0x01;
	
	/** Maximum size response. */
	private final static short RESPONSE_CHUNCK_SIZE = 256;
	
	/** A command code for all commands that should be processed by the TPM implementation. */
	private static final byte TPM_APDU_COMMAND_CODE = 0x00;
	
	/** A flag indicating that more command data is to come. Command is processed if this flag is not set. */
	private static final byte TPM_APDU_COMMAND_PARAMETER_P1_WAIT_FOR_MORE = 0x01;
	
	/**
	 * The current offset in the extended buffer when the response is length is greater that 256 bytes.
	 */
	private short offsetExtendedBuffer = 0;
	private short responseLength = 0;
 
	private TPM2Applet(byte[] installBuffer, short parameterOffset, short parameterLength){ 
		extendedBuffer = new byte[EXTENDED_APDU_BUFFER_SIZE]; 
		tpm = new TPM(installBuffer, parameterOffset, parameterLength);
	}
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		
		// The auth value for Endorsement key is passed as applet install parameter.
		// length of application id .. first byte
		byte appletIdLength = bArray[bOffset]; 
		
		// offset of applet info.
		short offset = (byte)(bOffset + appletIdLength + 1);
		
		// offset of parameter length.
		byte appletInfoLength = bArray[offset];
		 
		//Offset install parameter.
		offset = (short) (offset + appletInfoLength + 1);
		 
		byte paramLength = bArray[offset];
		
		new TPM2Applet(bArray, (short)(offset + 1), paramLength).register(bArray, (short) (bOffset + 1),bArray[bOffset]);
	}

	public void process(APDU apdu) { 
		if (selectingApplet()) {
			tpm.initTpm();
			return;
		}
		
		short outgoingLength = RESPONSE_CHUNCK_SIZE;
		
		byte[] buffer = apdu.getBuffer();
		short incomingLength = apdu.setIncomingAndReceive();
		switch (buffer[ISO7816.OFFSET_INS]) {
		
			case (byte) TPM_APDU_COMMAND_CODE:	
				
				// Clear extended buffer if any response remains from previous command.
				if(responseLength > 0){
					clearExtededBuffer();
				}
			
				// Return error if command size is greater than the size of the extended buffer.
				if((short)(offsetExtendedBuffer + incomingLength) > EXTENDED_APDU_BUFFER_SIZE){
					clearExtededBuffer();
					ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					return;
				}
				Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, extendedBuffer, offsetExtendedBuffer, incomingLength); 
				offsetExtendedBuffer += incomingLength;
				
				if(buffer[ISO7816.OFFSET_P1] == TPM_APDU_COMMAND_PARAMETER_P1_WAIT_FOR_MORE){
					// skip processing command and wait for more data.
					return;	 
				}
				
				responseLength = tpm.processCommand(extendedBuffer, (short)0, offsetExtendedBuffer, extendedBuffer, (short)0);		  
				
				if(responseLength > RESPONSE_CHUNCK_SIZE){
					outgoingLength = RESPONSE_CHUNCK_SIZE;
				}else{
					outgoingLength = responseLength;
				}
				Util.arrayCopy(extendedBuffer, (short)0, buffer, (short)0, outgoingLength);
				apdu.setOutgoingAndSend((short)0, outgoingLength);  
				
				if(outgoingLength == responseLength){
					clearExtededBuffer();
				}else{
					offsetExtendedBuffer = outgoingLength;
				}
				break;
				
			case (byte) EXTENDED_BUFFER_GET_DATA:
				
				if(offsetExtendedBuffer < responseLength){
					outgoingLength = (short)(responseLength - offsetExtendedBuffer);
					if(outgoingLength > RESPONSE_CHUNCK_SIZE){
						outgoingLength = RESPONSE_CHUNCK_SIZE;
					}
					
					Util.arrayCopy(extendedBuffer, offsetExtendedBuffer, buffer, (short)0, outgoingLength);
					apdu.setOutgoingAndSend((short)0, outgoingLength);
					offsetExtendedBuffer += outgoingLength; 
					
					if(offsetExtendedBuffer == responseLength){
						clearExtededBuffer();
					}
				} 
				break;
				  
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		} 
	}
	
	private void clearExtededBuffer(){
		Util.arrayFillNonAtomic(extendedBuffer, (short)0, EXTENDED_APDU_BUFFER_SIZE, (byte)0);
		responseLength = 0;
		offsetExtendedBuffer = 0;
	}
}