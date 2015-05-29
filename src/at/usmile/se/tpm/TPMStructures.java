package at.usmile.se.tpm;
/**
 * TPM 2.0 Structures
 * 
 * @author Michael Hölzl
 * @version 0.1
 */
public class TPMStructures {
	
	public class TPMI_ALG_HASH {
		short TPM_ALG_ERROR = 0000;
		short TPM_ALG_FIRST = 0001;
		short TPM_ALG_RSA = 0001;
		short TPM_ALG_SHA = (0004);
		short TPM_ALG_SHA1 = (0004);
		short TPM_ALG_HMAC = (0005);
		short TPM_ALG_AES = (0006);
		short TPM_ALG_XOR = (0x000A);
		short TPM_ALG_SHA256 = (0x000B);
		short TPM_ALG_SHA384 = (0x000C);
		short TPM_ALG_SHA512 = (0x000D);
		short TPM_ALG_NULL = (0x0010);
		short TPM_ALG_LAST = (0x0044);
		
		private short mAlgorithm;
		public TPMI_ALG_HASH(short algo){
			mAlgorithm = algo;
		}
		public short getAlgorithm(){
			return mAlgorithm;
		}
	}

	public class TPMI_RH_NV_INDEX{
		byte[] index = new byte[3]; //TPMI_RH_NV_INDEX (first 24 bits indes, last 8 bits index range)
		byte range;
	}
	
	public class TPMS_NV_PUBLIC{
		TPMI_RH_NV_INDEX index; //TPMI_RH_NV_INDEX (first 24 bits indes, last 8 bits index range)
		TPMI_ALG_HASH algorithm; //TPMI_ALG_HASH
		byte[] attributes = new byte[4];//TPMA_NV (32bit bitset) 
		byte[] authpolicy = new byte[3];//TPM2B_DIGEST (24 bit = 16 bit size, 1 byte buffer)
		short dataSize; //UINT16
	}
	
	public class TPM2B_NV_PUBLIC{
		short size;
		TPMS_NV_PUBLIC nvPublic;		
	}
}
