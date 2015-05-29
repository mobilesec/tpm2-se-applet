package at.usmile.se.tpm;

import javacard.framework.Util;
/**
 * TPM 2.0 Data store
 * 
 * @author Michael Hölzl
 * @version 0.1
 */
public class TPM_NV_Data {
	private static final short NV_DEFAULT_DATA_SIZE = 255;
	private short index;
	private short size;
	private byte[] mDataEntry = new byte[NV_DEFAULT_DATA_SIZE];

	public TPM_NV_Data(){
		this(null);
	}

	public TPM_NV_Data(byte[] data){
		setIndex((short) 0);
		setSize((short) 0);
		setDataEntry(data, (short)0, (short)0);
	}
	public short getIndex() {
		return index;
	}
	public void setIndex(short index2) {
		this.index = index2;
	}
	
	public byte[] getDataEntry() {
		return mDataEntry;
	}
	public void setDataEntry(byte[] _dataEntry) {
		setDataEntry(_dataEntry, (short)0, (short)0);		
	}
	public void setDataEntry(byte[] _dataEntry, short srcOffset, short srcSize) {
		short length;
		if(_dataEntry==null){
			Util.arrayFillNonAtomic(mDataEntry, (short) 0, NV_DEFAULT_DATA_SIZE, (byte)0);			
		} else {
			if(srcSize>NV_DEFAULT_DATA_SIZE){
				length = NV_DEFAULT_DATA_SIZE;
			} else{
				length = srcSize;
			}
			Util.arrayCopyNonAtomic(_dataEntry, srcOffset, mDataEntry, (short) 0, length);
		}
	}
	public short getSize() {
		return size;
	}
	public void setSize(short size) {
		this.size = size;
	}
}
