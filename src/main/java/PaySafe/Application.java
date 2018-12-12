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

import Crypto.Constants;

public class Application {

	
	public static int chooseTelefoneNumber(String userNumber, Scanner reader) {
		int telefoneNumber = 0;
		System.out.println("Whom do you want to pay? ");
		System.out.println("Select a number: ");
		if(userNumber.equals("1")) {
			System.out.println("1 -- Bob");
			System.out.println("2 -- Charlie");
			int receiverNumber = reader.nextInt(); 
			if(receiverNumber == 1) {
				telefoneNumber = Constants.BOB_NUMBER;
			} else {
				telefoneNumber = Constants.CHARLIE_NUMBER;
			}
		} else if(userNumber.equals("2")) {
			System.out.println("1 -- Alice");
			System.out.println("2 -- Charlie");
			int receiverNumber = reader.nextInt(); 
			if(receiverNumber == 1) {
				telefoneNumber = Constants.ALICE_NUMBER;
			} else {
				telefoneNumber = Constants.CHARLIE_NUMBER;
			}
		} else {
			System.out.println("1 -- Alice");
			System.out.println("2 -- Bob");
			int receiverNumber = reader.nextInt(); 
			if(receiverNumber == 1) {
				telefoneNumber = Constants.ALICE_NUMBER;
			} else {
				telefoneNumber = Constants.BOB_NUMBER;
			}
		}
		return telefoneNumber;
	}
	
	
	public static void main(String[] args) throws IOException, UnrecoverableKeyException, KeyStoreException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException, CertificateException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {
		
		PaySafeClient client = null;
		int telefoneNumber = 0;
		System.out.println("-------------------Welcome To PaySafe Secure SMS payment service------------------------");
		System.out.println("----------------------------------------------------------------------------------------");
		
		Scanner reader = new Scanner(System.in);
		String userNumber = null;
		int myNumber = 0;
		int init =0;
		while(init ==0) {
			System.out.println("Select a number to init: ");
			System.out.println("1 -- Alice");
			System.out.println("2 -- Bob");
			System.out.println("3 -- Charlie");
			userNumber = reader.nextLine();
			switch (userNumber.trim()) {
	        case "1":  client=new PaySafeClient(Constants.ALICE);
	        		 myNumber = Constants.ALICE_NUMBER;
	        		 init=1;
	                 break;
	        case "2":  client=new PaySafeClient(Constants.BOB);
	        		 init=1;
	        		 myNumber = Constants.BOB_NUMBER;
	        		 break;
	        case "3":  client=new PaySafeClient(Constants.CHARLIE);
	        		 init=1;
	        		 myNumber = Constants.CHARLIE_NUMBER;
	        		 break;
	        default: System.out.println("\nThe '"+userNumber+ "' is not a valid number!");
	        		continue;
			}
		}
		while(true) {
			try {
	
				System.out.println("Choose pretended operation: ");
				System.out.println("1 -- Perform payment");
				System.out.println("2 -- Check balance");
				System.out.println("3 -- Exit");
		 
				System.out.println("Enter a number: ");
				int n = Integer.parseInt(reader.nextLine()); 
				if(n == 1) {
					telefoneNumber = chooseTelefoneNumber(userNumber, reader);
					System.out.println("Introduce amount to send: ");
					double amount = reader.nextDouble(); 				
					System.out.println(client.sendMessageUDP(telefoneNumber, amount, Constants.PAY_OPERATION));
				} else if(n == 2) {
					System.out.println(client.sendMessageUDP(myNumber, -1, Constants.CHECK_BALANCE_OPERATION));
				} else if(n == 3) {
				    System.exit(0);
				}
					 	
			}catch(Exception e) {
				System.out.println("Bad Input! Enter again");
			}
		}
	}
}
