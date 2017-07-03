/**
 * Defines utils for TPM handles.
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

public class TPMHandleUtil {  
  
		/**
		 * Gets the type of this handle. (The MSO value)
		 * 
		 * @param buffer
		 *            the buffer containing the handle value.
		 * @param offset
		 *            the offset of where the handle value starts.
		 * @return the new offset in buffer after copying handle value.
		 */
		public static byte getType(byte[] buffer, short offset) {
			return buffer[offset];
		}

		/**
		 * Gets the value of the two list significant bytes. Used for ease of
		 * implementation to identify resources.
		 * 
		 *  *
		 * @param buffer
		 *            the buffer containing the handle value.
		 * @param offset
		 *            the offset of where the handle value starts.
		 * 
		 * @return the short number value from the two list significant bytes.
		 */
		public static short getNumber(byte[] buffer, short offset) {
			return Util.getShort(buffer, (short) (offset + 2));
		}

		
		/**
		 * Validates a handle inside buffer with specified handle parameters.
		 * The handle is valid if the type is is equal to the expected type, if number (last two list significant bytes) is equl to the expected number, and the the second byte should be set to zero. 
		 * 
		 * @param handleBuffer
		 * 				the buffer containing a handle.
		 * @param offset
		 * 				the offset in handle1Buffer where the handle value starts from.
		 * @param expectedType
		 * 				the expected handle type. The most significant byte.
		 * @param expectedNumber
		 * 				the expected handle number. The two list significant bytes.
		 * @return true if the content of the handle match the expected handle properties, false otherwise. 
		 */
		public static boolean validateHandle(byte[] handleBuffer, short offset, byte expectedType, short expectedNumber){
			if(handleBuffer[offset] != expectedType){
				return false;
			}
			if(handleBuffer[(short)(offset + 1)] != 0x00){
				return false;
			}
			short number = Util.getShort(handleBuffer, (short)(offset + 2)); 
			return expectedNumber == number;
		} 
		
		/** 
		 * Writes a handle value to a buffer.
		 * 
		 * @param handleType
		 * 				the type of the handle.
		 * @param handleNumber
		 * 				the handle number.
		 * @param buffer
		 * 				the buffer to write to.
		 * @param offset
		 * 				the offset in buffer to start writing from.
		 * @return the new offset in the buffer.
		 */
		public static short writeHandle(byte handleType, short handleNumber, byte[] buffer,  short offset){
			buffer[offset] = handleType;
			buffer[(short)(offset + 1)] = 0x00;
			return Util.setShort(buffer, (short)(offset + 2), handleNumber); 
		}
}
