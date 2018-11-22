package Crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class CryptoManager {

    private PublicKey pubKey;
    private PrivateKey privKey;

    public CryptoManager() {}
    public CryptoManager(PublicKey publicKey, PrivateKey privateKey){
        
    	this.pubKey=publicKey;
    	this.privKey=privateKey;
        System.out.println("CRYPTO MANAGER STARTED");
    }
    
   
    public CipheredMessage makeCipheredMessage(Message message, PublicKey receiverPubKey){
        CipheredMessage cipheredMessage = null;
        try {
        	
        	
        	KeyAgreement ecdhU = KeyAgreement.getInstance("ECDH", "BC");
            ecdhU.init(privKey);
            ecdhU.doPhase(receiverPubKey,true);
            SecretKey aesKey = ecdhU.generateSecret("AES");
            byte[] iv = generateIV();

            //AES ciphering of Message
            byte[] cipheredContent = cipherContent(message, iv,aesKey);

            //Signature generation
            byte[] digitalSig;
            byte[] concatParams = toBytes(message);

            
            digitalSig = CryptoUtil.makeDigitalSignature(concatParams, privKey);
            IntegrityCheck integrityCheck = new IntegrityCheck(digitalSig);
            byte[] integrityCheckBytes = toBytes(integrityCheck);

            //AES ciphering of Signature and params
            byte[] cipheredIntegrityCheck = CryptoUtil.symCipher(integrityCheckBytes,iv, aesKey);
            cipheredMessage = new CipheredMessage(cipheredContent, cipheredIntegrityCheck);
        } catch (NoSuchAlgorithmException | IOException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            System.out.println("Cipher error1");
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Cipher error2");
        }
        return cipheredMessage;
    }

    /*public Message decipherCipheredMessage(CipheredMessage cipheredMessage, SecretKey key,PublicKey senderK) throws NoSuchProviderException{
        Message deciphMsg = null;
        try {
            byte[] decipheredContent = CryptoUtil.symDecipher(cipheredMessage.getContent(), key);
            deciphMsg = (Message) fromBytes(decipheredContent);
            byte[] decipheredIntegrityBytes = CryptoUtil.symDecipher(cipheredMessage.getIntegrityCheck(), key);
            IntegrityCheck check = (IntegrityCheck) fromBytes(decipheredIntegrityBytes);
            if(verifyIntegrity(deciphMsg, check, senderK)) return deciphMsg;
            else throw new IllegalStateException("Invalid Signature");
        } catch (ClassNotFoundException | IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            System.out.println("Decipher error...");
        }
        return deciphMsg;
    }*/
   
    public boolean verifyIntegrity(Message msg, IntegrityCheck check, PublicKey key) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, ClassNotFoundException, InvalidAlgorithmParameterException, NoSuchProviderException {
       return CryptoUtil.verifyDigitalSignature(check.getDigitalSignature(), toBytes(msg), key);
    }

    private byte[] cipherContent(Message message, byte[] iv, SecretKey skey){
        byte[] cipheredMessage = new byte[0];
        try {
            cipheredMessage = CryptoUtil.symCipher(toBytes(message), iv, skey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | IOException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return cipheredMessage;
    }

    private <T> byte[] toBytes(T toConvert) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        ObjectOutputStream os = new ObjectOutputStream(byteStream);
        os.writeObject(toConvert);
        os.flush();
        return byteStream.toByteArray();
    }

    private Object fromBytes(byte[] toConvert) throws IOException, ClassNotFoundException {
        ByteArrayInputStream byteInStream = new ByteArrayInputStream(toConvert);
        ObjectInputStream is = new ObjectInputStream(byteInStream);
        return is.readObject();
    }
    
    public PublicKey getPublicKey() {
    	return pubKey;
    }
    public PrivateKey getPrivateKey() {
    	return privKey;
    }
    private byte[] generateIV(){
        SecureRandom random = new SecureRandom();
        byte[] initializationVector = new byte[128/8];
        random.nextBytes(initializationVector);
        return initializationVector;
    }

    
}
