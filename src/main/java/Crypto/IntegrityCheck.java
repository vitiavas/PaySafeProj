package Crypto;

import java.io.Serializable;

import javax.xml.bind.DatatypeConverter;

public class IntegrityCheck implements Serializable{

    /**
	 * 
	 */
	private static final long serialVersionUID = 1214331689542769611L;
	private String digitalSignature;
    private int timestamp;
    
    public IntegrityCheck(){
    	
    }

    public IntegrityCheck(byte[] digitalSignature) {
    	StringBuffer toDigitalSignature = new StringBuffer();
        for (int i = 0; i < digitalSignature.length; ++i) {
        	toDigitalSignature.append(Integer.toHexString(0x0100 + (digitalSignature[i] & 0x00FF)).substring(1));
        }
        this.digitalSignature = toDigitalSignature.toString();
        
    }
    
    public byte[] getDigitalSignature() {
        return DatatypeConverter.parseHexBinary(digitalSignature);
    }
    
    public String getStringDigitalSignature() {
        return digitalSignature;
    }
    
    public boolean myEqual(IntegrityCheck ic) {
    	if(digitalSignature.equals(ic.getStringDigitalSignature())) {
    		return true;
    	}
		return false;
    }

}
