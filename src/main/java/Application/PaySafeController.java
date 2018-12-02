package Application;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.net.URLConnection;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import Crypto.CryptoUtil;

@RestController
@RequestMapping("dashboard")
public class PaySafeController {

    
    @RequestMapping("sendMessage")
    public void sendMessage(@RequestParam(value = "senderNumber") String senderNumber,
			@RequestParam(value = "receiverNumber") String receiverNumber,
			@RequestParam(value = "amount") String amount) throws CertificateException, NoSuchProviderException, KeyStoreException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException, CMSException, OperatorCreationException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {
    	
    	
        
    	// MAXIMIZE Key Size if necessary
    	int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
    	System.out.println("Max Key Size for AES : " + maxKeySize);
    	
    	Security.addProvider(new BouncyCastleProvider());
    	X509Certificate certificate = CryptoUtil.getCertificate();

    	
    	String secretMessage = senderNumber + " " + receiverNumber + " " + amount;
    	System.out.println("Original Message : " + secretMessage);
    	byte[] stringToEncrypt = secretMessage.getBytes();
    	
    	
		KeyPair pair = CryptoUtil.GenerateKeys();
		PrivateKey privateKey = pair.getPrivate();
	
    	byte[] dataWithDigitalSignature = CryptoUtil.makeDigitalSignature(stringToEncrypt, privateKey);
    	byte[] encryptedData = CryptoUtil.encryptDataWithPublicKey(dataWithDigitalSignature, certificate);
    	
    	
    	System.out.println("Encrypted Message : " + new String(encryptedData));
    	PublicKey publicKey = pair.getPublic();
    	BankController bank = BankController.getInstance();
    	bank.processMessage(encryptedData, publicKey);
    	 	
    }
    
    
    
    public void sendMessageOverNetwork(byte[] data) throws IOException {
		URL url = new URL("NãoSeiQualURLDoBanco");
		//Request for establishing the connection
		URLConnection conn = url.openConnection();
		conn.setRequestProperty("Content-type", "application/json");
		conn.setDoOutput(true);

		conn.setConnectTimeout(5000); // Connection timeout to 5 seconds
		
		// Open Stream to write (If connection is unsuccessful -> Exception)
		OutputStream os = conn.getOutputStream();
		OutputStream out = new BufferedOutputStream(os);
		BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(out));
		
        bw.close();
        out.close();
        os.close();

        // Wait for response here
        BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String line;
		String jsonText = "";
		while ((line = rd.readLine()) != null) {
            jsonText += line;
        }
        rd.close();
    }
    
       
}
