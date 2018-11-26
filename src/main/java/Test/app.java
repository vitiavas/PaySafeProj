package Test;

import Crypto.*;
import java.io.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class app {
	
	private static byte[] generateIV(){
        SecureRandom random = new SecureRandom();
        byte[] initializationVector = new byte[128/8];
        random.nextBytes(initializationVector);
        return initializationVector;
    }
	
	private static <T> byte[] toBytes(T toConvert) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        ObjectOutputStream os = new ObjectOutputStream(byteStream);
        os.writeObject(toConvert);
        os.flush();
        return byteStream.toByteArray();
    }
	private static Object fromBytes(byte[] toConvert) throws IOException, ClassNotFoundException {
        ByteArrayInputStream byteInStream = new ByteArrayInputStream(toConvert);
        ObjectInputStream is = new ObjectInputStream(byteInStream);
        return is.readObject();
    }
	public static void main(String[] args) throws IOException, UnrecoverableKeyException, KeyStoreException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException, CertificateException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {
		String m = "910984085 964089137 22232.22 1334";
		Security.addProvider(new BouncyCastleProvider());
		byte[] iv = generateIV();
		CryptoManager mn = new CryptoManager();
		byte[] b = toBytes(m);
		System.out.println("WWWW   " + b.length+Thread.currentThread().getContextClassLoader().getResourceAsStream("keys.jks"));
		String s = "123456";
		String s2 = "keys.jks";
		String s3 = "keystore";
		
		PrivateKey k = CryptoUtil.getPrivateKeyFromKeyStoreResource(s2, s3.toCharArray(), "server", s.toCharArray());
		if(k==null)
			System.out.println("shiiit");
		byte[] sig = CryptoUtil.makeDigitalSignature(b, k);
		System.out.println("WWWW   " + sig.length);
		Certificate c = CryptoUtil.getX509CertificateFromResource("server.cer");
		PublicKey k2 = c.getPublicKey();
		System.out.println(CryptoUtil.verifyDigitalSignature(sig, b, k2));
		
		PrivateKey k3 = CryptoUtil.getPrivateKeyFromKeyStoreResource(s2, s3.toCharArray(), "alice", s.toCharArray());
		Certificate c2 = CryptoUtil.getX509CertificateFromResource("alice.cer");
		
		KeyAgreement ecdhU = KeyAgreement.getInstance("ECDH", "BC");
	    ecdhU.init(k);
	    ecdhU.doPhase(c2.getPublicKey(),true);

	    KeyAgreement ecdhV = KeyAgreement.getInstance("ECDH", "BC");
	    ecdhV.init(k3);
	    ecdhV.doPhase(c.getPublicKey(),true);
	    
	    byte[] sK= ecdhU.generateSecret();
	    System.out.println(sK.length);
	    SecretKey originalKey = new SecretKeySpec(sK, 0, sK.length, "AES");
	    byte[] b2 = CryptoUtil.symCipher(b, iv,originalKey);
	    StringBuffer toContent = new StringBuffer();
        for (int i = 0; i < b2.length; ++i) {
        	toContent.append(Integer.toHexString(0x0100 + (b2[i] & 0x00FF)).substring(1));
        }
        StringBuffer toContent2 = new StringBuffer();
        for (int i = 0; i < sig.length; ++i) {
        	toContent2.append(Integer.toHexString(0x0100 + (sig[i] & 0x00FF)).substring(1));
        }
        StringBuffer toContent3 = new StringBuffer();
        for (int i = 0; i < iv.length; ++i) {
        	toContent3.append(Integer.toHexString(0x0100 + (iv[i] & 0x00FF)).substring(1));
        }
	    System.out.println(toContent.toString().length() + " " +toContent2.toString().length() + " "+ toContent3.toString().length());
	    
	    String message = toContent.toString() + " "+ toContent2.toString()+ " " +toContent3.toString();
	    System.out.println(message);
	    
	    String[] splited = message.split(" ");
	    
	    byte[] sK2= ecdhV.generateSecret();
	    System.out.println(sK.length);
	    SecretKey originalKey2 = new SecretKeySpec(sK2, 0, sK2.length, "AES");
	    
	    byte[] deciph = CryptoUtil.symDecipher(DatatypeConverter.parseHexBinary(splited[0]),DatatypeConverter.parseHexBinary(splited[2]), originalKey2);
	    System.out.println(fromBytes(deciph));
	    System.out.println(CryptoUtil.verifyDigitalSignature(DatatypeConverter.parseHexBinary(splited[1]), deciph, k2));
		
	}
}