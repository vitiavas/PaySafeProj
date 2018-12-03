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
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Application {

	public static void main(String[] args) throws IOException, UnrecoverableKeyException, KeyStoreException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException, CertificateException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {
		System.out.println("-------------------Welcome To PaySafe Secure SMS payment service------------------------");
		System.out.println("----------------------------------------------------------------------------------------");
		System.out.println("Choose pretended operation: ");
		System.out.println("1 -- Perform payment");
		System.out.println("2 -- Check balance");
		System.out.println("3 -- Deposit");
		PaySafeClient client = new PaySafeClient();

		Scanner reader = new Scanner(System.in);  
		System.out.println("Enter a number: ");
		int n = reader.nextInt(); 
		if(n == 1) {
			System.out.println("Introduce the receivers number: ");
			int receiverNumber = reader.nextInt(); 
			System.out.println("Introduce amount to send: ");
			int amount = reader.nextInt(); 
			// CONVERT TO A MESSAGE HERE AND DO ALL THE ENCRYPTION PROCESS
			client.sendMessageUDP("telefone Numbers");
		} else if(n == 2) {
			System.out.println("Introduce your number: ");
			int myNumber = reader.nextInt();
			String message = "Check Balance " + Integer.toString(myNumber);
			// CONVERT TO A MESSAGE HERE AND DO ALL THE ENCRYPTION PROCESS
			client.sendMessageUDP(message);

		} else if(n == 3) {
			
		}
		reader.close();

        
	}
}
