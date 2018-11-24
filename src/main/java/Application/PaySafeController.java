package Application;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.KeyTransRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputEncryptor;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;

@RestController
@RequestMapping("dashboard")
public class PaySafeController {


    public static final String ACCOUNT_SID = System.getenv("TWILIO_ACCOUNT_SID");
    public static final String AUTH_TOKEN = System.getenv("TWILIO_AUTH_TOKEN");
    
    @RequestMapping(value = "/test", method = RequestMethod.GET)
    public void test() {
    	System.out.println("TEST");
    }
    

    public X509Certificate getCertificate() throws CertificateException, NoSuchProviderException, FileNotFoundException {
    	CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
		X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(new FileInputStream("Certificate.cer"));
		return certificate;    	
    }
    @RequestMapping("sendMessage")
    public void sendMessage(@RequestParam(value = "senderNumber") String senderNumber,
			@RequestParam(value = "receiverNumber") String receiverNumber,
			@RequestParam(value = "amount") String amount) throws CertificateException, NoSuchProviderException, KeyStoreException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException, CMSException {
     
    	// MAXIMIZE Key Size if necessary
    	int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
    	System.out.println("Max Key Size for AES : " + maxKeySize);
    	
    	Security.addProvider(new BouncyCastleProvider());
    	X509Certificate certificate = getCertificate();
    	  
    	char[] keystorePassword = "password".toCharArray();
    	char[] keyPassword = "password".toCharArray();
    	  
    	KeyStore keystore = KeyStore.getInstance("PKCS12");
    	keystore.load(new FileInputStream("Baeldung.p12"), keystorePassword);
    	PrivateKey privateKey = (PrivateKey) keystore.getKey("baeldung", keyPassword);
    	
    	// TEST Encrypt/Descrypt Working
    	String secretMessage = "My password is 123456Seven";
    	System.out.println("Original Message : " + secretMessage);
    	byte[] stringToEncrypt = secretMessage.getBytes();
    	byte[] encryptedData = encryptData(stringToEncrypt, certificate);
    	System.out.println("Encrypted Message : " + new String(encryptedData));
    	byte[] rawData = decryptData(encryptedData, privateKey);
    	String decryptedMessage = new String(rawData);
    	System.out.println("Decrypted Message : " + decryptedMessage);
    	byte[] data = senderNumber.getBytes();
    	
//    	Twilio.init(ACCOUNT_SID, AUTH_TOKEN);
//    	Message message = Message.creator(
//    				new PhoneNumber(senderNumber), 
//    				new PhoneNumber(receiverNumber),
//    				"This is automatic message with money: " + amount).create();
    	
    }
    
    public static byte[] encryptData(byte[] data, X509Certificate encryptionCertificate) throws CertificateEncodingException, CMSException, IOException {
	    byte[] encryptedData = null;
	    if (null != data && null != encryptionCertificate) {
	    	CMSEnvelopedDataGenerator generator = new CMSEnvelopedDataGenerator();
	        JceKeyTransRecipientInfoGenerator jceKey = new JceKeyTransRecipientInfoGenerator(encryptionCertificate);
	        generator.addRecipientInfoGenerator(jceKey);
	        CMSTypedData msg = new CMSProcessableByteArray(data);
	        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider("BC").build();
	        CMSEnvelopedData cmsEnvelopedData = generator.generate(msg,encryptor);
	        encryptedData = cmsEnvelopedData.getEncoded();
	    }
	    return encryptedData;
	}
    
    public static byte[] decryptData(byte[] encryptedData, PrivateKey decryptionKey) throws CMSException {
	    byte[] decryptedData = null;
	    if (null != encryptedData && null != decryptionKey) {
	        CMSEnvelopedData envelopedData = new CMSEnvelopedData(encryptedData);
	        @SuppressWarnings("unchecked")
			Collection<RecipientInformation> recipients = envelopedData.getRecipientInfos().getRecipients();
	        KeyTransRecipientInformation recipientInfo  = (KeyTransRecipientInformation) recipients.iterator().next();
	        JceKeyTransRecipient recipient = new JceKeyTransEnvelopedRecipient(decryptionKey);
	        return recipientInfo.getContent(recipient);
	    }
	    return decryptedData;
	}
    
}
