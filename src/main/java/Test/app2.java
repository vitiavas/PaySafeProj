package Test;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

import Crypto.CryptoManager;
import Crypto.CryptoUtil;

public class app2 {

	public static void main(String[] args) throws CertificateException, IOException, UnrecoverableKeyException, KeyStoreException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());
		String s = "123456";
		String s2 = "server/server.jks";
		String s3 = "server";
		String s4 = "clients/alice.jks";
		PrivateKey k = CryptoUtil.getPrivateKeyFromKeyStoreResource(s2, s.toCharArray(), "server", s.toCharArray());
		if(k==null)
			System.out.println("shiiit");
		Certificate c2 = CryptoUtil.getX509CertificateFromResource("server/alice.cer");
		Certificate c = CryptoUtil.getX509CertificateFromResource("clients/server.cer");
		PrivateKey k3 = CryptoUtil.getPrivateKeyFromKeyStoreResource(s4, s.toCharArray(), "alice", s.toCharArray());
		CryptoManager cm = new CryptoManager(c.getPublicKey(),k,"964089137");
		
		
		CryptoManager cm2 = new CryptoManager(c2.getPublicKey(), k3, "910984085");
		byte[] message = cm2.makeCipheredMessage("964089137 22232.22 1334", c.getPublicKey());
		String numberReceived = new String(Arrays.copyOfRange(message, 0, 9));
		
		System.out.println(numberReceived);
		
		byte[] cipheredMessage = Arrays.copyOfRange(message, 9, message.length);
		int number = Integer.parseInt(numberReceived);
		
		byte[] decipheredMessage = cm.decipherCipheredMessage(cipheredMessage, c2.getPublicKey());
		String received = new String(decipheredMessage);
		String[] fields = received.split(" ");
        String cmd = fields[0];
        
        System.out.println(received);
	}
	
}
