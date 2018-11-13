package Crypto;

import java.io.Serializable;

import javax.xml.bind.DatatypeConverter;


public class CipheredMessage implements Serializable{

    /**
	 * 
	 */
	private static final long serialVersionUID = -8286624322954456950L;
	private String content;
    private String integrityCheck;

	
	public CipheredMessage(){
		
	}

    public CipheredMessage(byte[] content, byte[] integrityCheck) {
    	StringBuffer toContent = new StringBuffer();
        for (int i = 0; i < content.length; ++i) {
        	toContent.append(Integer.toHexString(0x0100 + (content[i] & 0x00FF)).substring(1));
        }
        StringBuffer toIntegrityCheck = new StringBuffer();
        for (int i = 0; i < integrityCheck.length; ++i) {
        	toIntegrityCheck.append(Integer.toHexString(0x0100 + (integrityCheck[i] & 0x00FF)).substring(1));
        }
        this.content = toContent.toString();
        this.integrityCheck = toIntegrityCheck.toString();
        
    }
    
    public byte[] getIntegrityCheck() {
        return DatatypeConverter.parseHexBinary(integrityCheck);
    }
    
    public byte[] getContent() {
        return DatatypeConverter.parseHexBinary(content);
    }
    
    public String getStringContent(){
    	return content;
    }
    public String getStringIntegrityCheck(){
    	return integrityCheck;
    }

    @Override
    public String toString() {
        return new String(content);
    }

}
