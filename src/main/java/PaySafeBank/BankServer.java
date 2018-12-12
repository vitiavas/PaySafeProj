package PaySafeBank;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;

import org.bouncycastle.util.Arrays;

import Crypto.Constants;
import Crypto.CryptoManager;
import Crypto.CryptoUtil;

public class BankServer extends Thread{
    private DatagramSocket socket;
    private boolean running;
    private byte[] buf = new byte[140];
    private CryptoManager cm;
    
    public HashMap<Integer, PublicKey> clients;
    private HashMap<Integer, Double> accounts;
    private HashMap<Integer, Long> timestamps;
    private HashMap<Integer, String> phoneNumbers;
    

    public PublicKey getClientPublicKey(int number) {
    	return clients.get(number);
    }
    
    public void initExistentClientsData(PrivateKey privateKey, Certificate certificate) throws CertificateException, IOException {
    	cm = new CryptoManager(certificate.getPublicKey(), privateKey, Constants.SERVER_NUMBER);
        
        //filling clients
        clients = new HashMap<Integer, PublicKey>();
        System.out.println("Starting clients certificates and accounts...");
        certificate = CryptoUtil.getX509CertificateFromResource(Constants.SERVER_FOLDER + Constants.ALICE_CERTIFICATE);
        clients.put(Constants.ALICE_NUMBER, certificate.getPublicKey());
        
        certificate = CryptoUtil.getX509CertificateFromResource(Constants.SERVER_FOLDER + Constants.BOB_CERTIFICATE);
        clients.put(Constants.BOB_NUMBER, certificate.getPublicKey());
        
        certificate = CryptoUtil.getX509CertificateFromResource(Constants.SERVER_FOLDER + Constants.CHARLIE_CERTIFICATE);
        clients.put(Constants.CHARLIE_NUMBER, certificate.getPublicKey());
        
        //filling accounts
        accounts = new HashMap<Integer,Double>();
        
        accounts.put(Constants.ALICE_NUMBER, 100.00);
        accounts.put(Constants.BOB_NUMBER, 100.00);
        accounts.put(Constants.CHARLIE_NUMBER, 100.00);
        
        phoneNumbers = new HashMap<Integer, String>();

        phoneNumbers.put(Constants.ALICE_NUMBER, Constants.ALICE);
        phoneNumbers.put(Constants.BOB_NUMBER, Constants.BOB);
        phoneNumbers.put(Constants.CHARLIE_NUMBER, Constants.CHARLIE);
        
        timestamps = new HashMap<Integer,Long>();
        
        timestamps.put(Constants.ALICE_NUMBER, (long) -1);
        timestamps.put(Constants.BOB_NUMBER, (long) -1);
        timestamps.put(Constants.CHARLIE_NUMBER, (long) -1);
        
        System.out.println("Current clients balances: ");
        System.out.println("Alice : " + accounts.get(Constants.ALICE_NUMBER));
        System.out.println("Bob : " + accounts.get(Constants.BOB_NUMBER));
        System.out.println("Charlie : " + accounts.get(Constants.CHARLIE_NUMBER));

    }
    
    public BankServer() throws UnrecoverableKeyException, KeyStoreException, CertificateException, IOException {
        
    	socket = new DatagramSocket(6666);
        
        PrivateKey privateKey = CryptoUtil.getPrivateKeyFromKeyStoreResource(Constants.KEYSTORE, Constants.PASSWORD.toCharArray(), 
        							Constants.ALIAS, Constants.PASSWORD.toCharArray());
        
        Certificate certificate = CryptoUtil.getX509CertificateFromResource(Constants.SERVER_FOLDER + Constants.SERVER_CERTIFICATE);
        
        initExistentClientsData(privateKey, certificate);
        
    }
    
    public byte[] checkBalance(String[] fields, byte[] sendData, int number) {
		int receiver = Integer.parseInt(fields[1]);
		int timestamp = Integer.parseInt(fields[2]);
		double receiverBalance = accounts.get(receiver);
		if(timestamp >= 0) {
			String content = "Your Balance is: " + receiverBalance;
			System.out.println(content);
			sendData = cm.makeCipheredMessage(content, clients.get(number));
		} else {
			String content = Constants.GENERIC_ABORTED;
			sendData = cm.makeCipheredMessage(content, clients.get(number));
		}	
		return sendData;
    }
    
    public boolean transfer(int sender, int receiver, double amount) {
		String senderName = phoneNumbers.get(sender);
		String receiverName = phoneNumbers.get(receiver);
		double senderBalance = accounts.get(sender);
		double receiverBalance = accounts.get(receiver);
		System.out.println(senderName + " balance : " + senderBalance);
		System.out.println(receiverName + " balance : " + receiverBalance);
		System.out.println(senderName + " sends " + amount + " to " + receiverName);
		senderBalance-=amount;
		receiverBalance+=amount;
		accounts.put(sender, senderBalance);
		accounts.put(receiver, receiverBalance);
		System.out.println(senderName + " balance : " + senderBalance);
		System.out.println(receiverName + " balance : " + receiverBalance);
		System.out.println("Success...");
		return true;
    }
    public byte[] processPayment(String[] fields, byte[] sendData, int number) {
		int receiver = Integer.parseInt(fields[1]);
		double amount = Double.parseDouble(fields[2]);
		int timestamp = Integer.parseInt(fields[3]);
		if((timestamp - timestamps.get(number)) == 1) {
			if(transfer(number,receiver , amount)) {
				DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
				Date date = new Date();
				String content = "Success! " + dateFormat.format(date);
				sendData = cm.makeCipheredMessage(content, clients.get(number));
			}
			else {
				String content = Constants.GENERIC_ABORTED;
				sendData = cm.makeCipheredMessage(content, clients.get(number));
			}
		}
		else {
			String content = Constants.GENERIC_ABORTED;
			sendData = cm.makeCipheredMessage(content, clients.get(number));
		}	
		return sendData;
    }
    
    public void run() {
        running = true;

        while (running) {
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            try {
            	System.out.println("Receiving packet...");
				socket.receive(packet);
				byte[] messageInBytes = Arrays.copyOfRange(packet.getData(), 0, packet.getLength());
				System.out.println("Received Message!");
				
				byte[] numberReceived = Arrays.copyOfRange(messageInBytes, 0, 9);
				byte[] cipheredMessage = Arrays.copyOfRange(messageInBytes, 9, messageInBytes.length);
				
				String numberReceivedString = new String(numberReceived);
				int number = Integer.parseInt(numberReceivedString);
				
				System.out.println("Deciphering...");
				byte[] decipheredMessage = cm.decipherCipheredMessage(cipheredMessage, clients.get(number));
				
				String received = new String(decipheredMessage);
				System.out.println("Deciphered message: " + received);
				
				
				String[] fields = received.split(" ");
	            String command = fields[0];
	            byte[] sendData = new byte[0];
	            
				switch(command) {
					case Constants.PAY_OPERATION:
						System.out.println("Process Payment");
						sendData = processPayment(fields, sendData, number);		
					break;
				case "charge":
					break;
				case Constants.CHECK_BALANCE_OPERATION:
	            	sendData = checkBalance(fields, sendData, number);
					break;
				}
				
				InetAddress IPAddress = packet.getAddress();
                int port = packet.getPort();
                
                
                DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, IPAddress, port);
	            socket.send(sendPacket);
	            
	            
			} catch (IOException e) {
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
        }
        socket.close();
    }
}


	
	
	

