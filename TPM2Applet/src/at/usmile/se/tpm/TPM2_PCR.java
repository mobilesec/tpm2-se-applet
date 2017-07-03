/**
 * Represents TPM2 PCR object.
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

package at.usmile.se.tpm;

import javacard.framework.Util;
import javacard.security.MessageDigest;

public class TPM2_PCR {
	
	private short number;
	
	private byte[] sha256Bank;
	
	private byte[] sha1Bank;
	 
	private short protectionGroupNumber;
	
	
	/**
	 * Constructor: Initializes a new PCR.
	 * 
	 * @param number
	 * 				the PCR number.
	 * @param protectionGroupNumber
	 * 				the protection group. PCR objects in the same group share the same auth value.
	 */
	public TPM2_PCR(short number, short protectionGroupNumber){
		this.number = number;
		sha1Bank = new byte[MessageDigest.LENGTH_SHA];
		sha256Bank = new byte[MessageDigest.LENGTH_SHA_256];
		this.protectionGroupNumber = protectionGroupNumber;
	}
	 
	/**
	 * Gets the PCR value in SHA 256 bank.
	 * 
	 * @param outPutBuffer
	 * 				the output buffer to write the PCR value to.
	 * @param offset
	 * 				the offset in the output buffer to start writing from.
	 * @return the new offset in the outputBuffer (offset + length of auth value).
	 */
	public short getSha256Bank(byte[] outPutBuffer, short offset){
		return Util.arrayCopy(sha256Bank, (short)0, outPutBuffer, offset, MessageDigest.LENGTH_SHA_256);
	}
	
	/**
	 * Sets the PCR value in SHA1 bank.
	 * 
	 * @param inputBuffer
	 * 				the input buffer to read the PCR value from.
	 * @param offset
	 * 				the offset in the input buffer to start reading from. 
	 */
	public void setSha256Bank(byte[] inputBuffer, short offset){
		Util.arrayCopy(inputBuffer, offset, sha256Bank, (short)0, MessageDigest.LENGTH_SHA_256);
	}
	
	/**
	 * Gets the PCR value in SHA1 bank.
	 * 
	 * @param outPutBuffer
	 * 				the output buffer to write the PCR value to.
	 * @param offset
	 * 				the offset in the output buffer to start writing from.
	 * @return the new offset in the outputBuffer (offset + length of auth value).
	 */
	public short getSha1Bank(byte[] outPutBuffer, short offset){
		return Util.arrayCopy(sha1Bank, (short)0, outPutBuffer, offset, MessageDigest.LENGTH_SHA);
	}
	
	/**
	 * Sets the PCR value in SHA1 bank.
	 * 
	 * @param inputBuffer
	 * 				the input buffer to read the PCR value from.
	 * @param offset
	 * 				the offset in the input buffer to start reading from. 
	 */
	public void setSha1Bank(byte[] inputBuffer, short offset){
		Util.arrayCopy(inputBuffer, offset, sha1Bank, (short)0, MessageDigest.LENGTH_SHA);
	}
	
	/**
	 * Resets pcr value in all banks.
	 */
	public void reset(){
		Util.arrayFillNonAtomic(sha1Bank, (short)0, MessageDigest.LENGTH_SHA, (byte)0);
		Util.arrayFillNonAtomic(sha256Bank, (short)0, MessageDigest.LENGTH_SHA_256, (byte)0);
	}
	
	/**
	 * Gets the protection group number of this PCR.
	 * 
	 * @return the protection group number.
	 */
	public short getProtectionGroupNumber(){
		return protectionGroupNumber;
	}
	
	/** 
	 * Gets the PCR number.
	 * 
	 * @return the PCR number.
	 */
	public short getNumber(){
		return number;
	}

}
