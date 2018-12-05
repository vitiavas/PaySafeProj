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
		
		PaySafeClient client = null;
		
		System.out.println("-------------------Welcome To PaySafe Secure SMS payment service------------------------");
		System.out.println("----------------------------------------------------------------------------------------");
		
		Scanner reader = new Scanner(System.in);
		System.out.println("Select a number to init:");
		System.out.println("1-Alice");
		System.out.println("2-Bob.");
		System.out.println("3-Charlie.");
		String userNumer = reader.nextLine();
		
		int init =0;
		while(init ==0) {
			switch (userNumer.trim()) {
	        case "1":  client=new PaySafeClient("Alice");
	        		 init=1;
	                 break;
	        case "2":  client=new PaySafeClient("Bob");
	        		 init=1;
	        		 break;
	        case "3":  client=new PaySafeClient("Charlie");
	        		 init=1;
	        		 break;
	        default: System.out.println("\nThe '"+userNumer+ "' is not a valid number!");
	        		continue;
			}
		}
		
		while(true) {
			System.out.println("Choose pretended operation: ");
			System.out.println("1 -- Perform payment");
			System.out.println("2 -- Check balance");
			System.out.println("3 -- Deposit");
			System.out.println("4 -- Exit");
	 
			System.out.println("Enter a number: ");
			int n = reader.nextInt(); 
			if(n == 1) {
				System.out.println("Introduce the receivers number: ");
				int receiverNumber = reader.nextInt(); 
				System.out.println("Introduce amount to send: ");
				double amount = reader.nextDouble(); 
				// CONVERT TO A MESSAGE HERE AND DO ALL THE ENCRYPTION PROCESS
				client.sendMessageUDP("pay " + receiverNumber + " "+ amount, "pay");
			} else if(n == 2) {
				System.out.println("Introduce your number: ");
				int myNumber = reader.nextInt();
				String message = "Check Balance " + Integer.toString(myNumber);
				// CONVERT TO A MESSAGE HERE AND DO ALL THE ENCRYPTION PROCESS
				client.sendMessageUDP(message,"check");
	
			} else if(n == 3) {
				
			}
			else if(n==4)
				break;
			
		}
		reader.close();
        
	}
}
