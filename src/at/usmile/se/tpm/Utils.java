package at.usmile.se.tpm;

public class Utils {
	
	public static short byteArrayToInt(byte[] b) 
	{
	    return byteArrayToInt(b, (short)0, (short) 4);
	}
	public static short byteArrayToInt(byte[] b, short offset, short arrayLength) 
	{
		short value = 0;
	    for (short i = 0; i < arrayLength; i++) {
	    	short shift = (short) ((arrayLength - 1 - i) * 8);
	        value += (b[offset+i] & 0x000000FF) << shift;
	    }
	    return value;
	}

}
