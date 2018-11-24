package Application;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import Crypto.CryptoUtil;

@RestController
@RequestMapping("bank")
public class BankController {

	private static final BankController instance = new BankController();
	
	private BankController() {
		// Singleton Object
	}

	public static BankController getInstance(){
		return instance;
	}
	
	
    public void processMessage(byte[] encryptedData, PublicKey publicKey) throws CertificateException, NoSuchProviderException, KeyStoreException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException, CMSException, InvalidKeyException {
     
    	// MAXIMIZE Key Size if necessary
    	int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
    	System.out.println("Max Key Size for AES : " + maxKeySize);
    	
    	
    	Security.addProvider(new BouncyCastleProvider());
    	char[] keystorePassword = "password".toCharArray();
    	char[] keyPassword = "password".toCharArray();
    	KeyStore keystore = KeyStore.getInstance("PKCS12");
    	keystore.load(new FileInputStream("Baeldung.p12"), keystorePassword);
    	PrivateKey privateKey = CryptoUtil.getPrivateKeyFromKeyStore("baeldung", keyPassword, keystore);	
    	
    	byte[] signature = CryptoUtil.decryptDataWithPrivateKey(encryptedData, privateKey);
    	// AQUI fico com a signature e não consigo obter o plaintext para depois verificar assinatura digital ????
    	String decryptedMessage = new String(signature);

    	
    	if(CryptoUtil.verifyDigitalSignature(encryptedData, signature, publicKey)) {
        	System.out.println("Message is Authentic, Non-repudiation granted"); 
    	} else {
        	System.out.println("Digital Signature == false");     		
    	}
    	
    	System.out.println("Decrypted Message : " + decryptedMessage);
    	
    }
	
}
