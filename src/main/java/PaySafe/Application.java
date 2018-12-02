package PaySafe;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Application {
    private static final String DEFAULT_IP = "127.0.0.1";
    private static final int DEFAULT_PORT = 6666;
	public static void main(String[] args) throws IOException, UnrecoverableKeyException, KeyStoreException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException, CertificateException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {

		PaySafeClient client = new PaySafeClient();
		
		client.startConnection(DEFAULT_IP, DEFAULT_PORT);
        
		client.sendMessage("hello server");
		client.sendMessage("telefone Numbers");
		client.stopConnection();

		
	}
}
