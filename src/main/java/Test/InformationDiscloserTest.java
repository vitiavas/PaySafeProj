package Test;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.crypto.BadPaddingException;

import org.bouncycastle.util.Arrays;
import org.junit.Assert;
import org.junit.Test;

import Crypto.Constants;
import PaySafe.PaySafeClient;

public class InformationDiscloserTest {
	
	@Test
	public void run()
	{	
		String received=null;
		
		try {
			PaySafeClient client = new PaySafeClient(Constants.ALICE);
			PaySafeClient client2 = new PaySafeClient(Constants.BOB);
			
			byte[] b = client.cipherAMessage("ola");
			byte[] cipheredMessage = Arrays.copyOfRange(b, 9, b.length);
			byte[] decipheredMessage = client2.decipherAMessage(cipheredMessage);
			received = new String(decipheredMessage);

		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		Assert.assertNull(received);
		
	}

}
