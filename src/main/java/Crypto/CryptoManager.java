package Crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.Arrays;

public class CryptoManager {

    private PublicKey pubKey;
    private PrivateKey privKey;
    private String number;

    public CryptoManager() {}
    public CryptoManager(PublicKey publicKey, PrivateKey privateKey, String number){
        
    	this.pubKey=publicKey;
    	this.privKey=privateKey;
    	this.number=number;
        System.out.println("CRYPTO MANAGER STARTED");
    }
    
   
    public byte[] makeCipheredMessage(String message, PublicKey receiverPubKey){
    	byte[] finalMessage = null ;
        try {
        	
        	
        	KeyAgreement ecdhU = KeyAgreement.getInstance("ECDH", "BC");
            ecdhU.init(privKey);
            ecdhU.doPhase(receiverPubKey,true);
            byte[] sK = ecdhU.generateSecret();
            SecretKey aesKey = new SecretKeySpec(sK, 0, sK.length, "AES");
            byte[] iv = generateIV();

            //AES ciphering of Message
            byte[] cipheredContent = cipherContent(message, iv,aesKey);

            //Signature generation
            byte[] digitalSig = CryptoUtil.makeDigitalSignature(message.getBytes(), privKey);

            //AES ciphering of Signature and params
            byte[] cipheredSignature = CryptoUtil.symCipher(digitalSig,iv, aesKey);
            
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(number.getBytes());
            baos.write(cipheredContent);
            baos.write(cipheredSignature);
            baos.write(iv);
            finalMessage = baos.toByteArray();
        } catch (NoSuchAlgorithmException | IOException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            System.out.println("Cipher error1");
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Cipher error2");
        }
        return finalMessage;
    }

    public byte[] decipherCipheredMessage(byte[] cipheredMessage, PublicKey senderK) throws NoSuchProviderException{
    	byte[] decipheredContent = null;
        try {
        	
        	KeyAgreement ecdhU = KeyAgreement.getInstance("ECDH", "BC");
            ecdhU.init(privKey);
            ecdhU.doPhase(senderK,true);
            byte[] sK = ecdhU.generateSecret();
            SecretKey aesKey = new SecretKeySpec(sK, 0, sK.length, "AES");
        	
            int length = cipheredMessage.length;
            int ivLength = length - 17;
            int sigLength = ivLength-54;
            
            byte[] iv = Arrays.copyOfRange(cipheredMessage, ivLength, length);
            byte[] sig = Arrays.copyOfRange(cipheredMessage, sigLength, ivLength);
            byte[] cipheredContent = Arrays.copyOfRange(cipheredMessage, 9, sigLength);
        	
        	
            decipheredContent = CryptoUtil.symDecipher(cipheredContent, iv, aesKey);            
            byte[] decipheredSignature = CryptoUtil.symDecipher(sig, iv, aesKey);
          
            if(verifyIntegrity(decipheredContent, decipheredSignature, senderK)) return decipheredContent;
            else throw new IllegalStateException("Invalid Signature");
        } catch (ClassNotFoundException | IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            System.out.println("Decipher error...");
        }
        return decipheredContent;
    }
   
    public boolean verifyIntegrity(byte[] msg, byte[] sig, PublicKey key) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, ClassNotFoundException, InvalidAlgorithmParameterException, NoSuchProviderException {
       return CryptoUtil.verifyDigitalSignature(sig, msg, key);
    }

    private byte[] cipherContent(String message, byte[] iv, SecretKey skey){
        byte[] cipheredMessage = new byte[0];
        try {
            cipheredMessage = CryptoUtil.symCipher(message.getBytes(), iv, skey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return cipheredMessage;
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
