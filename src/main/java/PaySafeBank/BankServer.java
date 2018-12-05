package PaySafeBank;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.Arrays;

import Crypto.CryptoManager;
import Crypto.CryptoUtil;

public class BankServer extends Thread{
    private DatagramSocket socket;
    private boolean running;
    private byte[] buf = new byte[120];
    private CryptoManager cm;
    
    private static final String KEYSTORE = "server/server.jks";
    private static final String PASSWORD = "123456";
    private static final String ALIAS = "server";
    private static final String CER = "server/";
    
    private static final int ALICE_NUMBER = 910984085;
    private static final String SERVER_NUMBER = "964089137";
    private static final int CHARLIE_NUMBER = 913330533;
    private static final int BOB_NUMBER = 964512431;
    
    private HashMap<Integer, PublicKey> clients;
    private HashMap<Integer, Double> accounts;
    private HashMap<Integer, Long> timestamps;
    
	/**
	 Main function start the bank server on port 6666
	 * @throws KeyStoreException 
	 * @throws UnrecoverableKeyException 
	 * @throws IOException 
	 * @throws CertificateException 
	 */

    public BankServer() throws UnrecoverableKeyException, KeyStoreException, CertificateException, IOException {
        socket = new DatagramSocket(6666);
        
        PrivateKey privateKey = CryptoUtil.getPrivateKeyFromKeyStoreResource(KEYSTORE, PASSWORD.toCharArray(), ALIAS, PASSWORD.toCharArray());
        Certificate c = CryptoUtil.getX509CertificateFromResource(CER+"server.cer");
        cm = new CryptoManager(c.getPublicKey(), privateKey, SERVER_NUMBER);
        
        //filling clients
        clients = new HashMap<Integer, PublicKey>();
        
        c = CryptoUtil.getX509CertificateFromResource(CER+"alice.cer");
        clients.put(ALICE_NUMBER, c.getPublicKey());
        
        c = CryptoUtil.getX509CertificateFromResource(CER+"bob.cer");
        clients.put(BOB_NUMBER, c.getPublicKey());
        
        c = CryptoUtil.getX509CertificateFromResource(CER+"charlie.cer");
        clients.put(CHARLIE_NUMBER, c.getPublicKey());
        
        //filling accounts
        accounts = new HashMap<Integer,Double>();
        
        accounts.put(ALICE_NUMBER, 100.00);
        accounts.put(BOB_NUMBER, 100.00);
        accounts.put(CHARLIE_NUMBER, 100.00);
        
        timestamps = new HashMap<Integer,Long>();
        
        timestamps.put(ALICE_NUMBER, (long) 0);
        timestamps.put(BOB_NUMBER, (long) 0);
        timestamps.put(CHARLIE_NUMBER, (long) 0);
        
        
    }
    
    public void checkBalance(int number) {
    	// BALANCE CHECKING PROCESS
    }
    
    public boolean transfer(int sender, int receiver, double amount) {
		return false;
    	
    }
    
    
    public void run() {
        running = true;
 
        while (running) {
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            try {
            	System.out.println("Receiving packet...");
				socket.receive(packet);
				
				byte[] message = packet.getData();
				String numberReceived = new String(Arrays.copyOfRange(message, 0, 9));
				byte[] cipheredMessage = Arrays.copyOfRange(message, 9, message.length);
				int number = Integer.parseInt(numberReceived);
				
				byte[] decipheredMessage = cm.decipherCipheredMessage(cipheredMessage, clients.get(number));
				String received = new String(decipheredMessage);
				String[] fields = received.split(" ");
	            String cmd = fields[0];
	            byte[] sendData = new byte[0];
				
				switch(cmd) {
				
				case "pay":
					int receiver = Integer.parseInt(fields[1]);
					double amount = Double.parseDouble(fields[2]);
					int timestamp = Integer.parseInt(fields[3]);
					if((timestamp - timestamps.get(numberReceived)) == 1) {
						if(transfer(number,receiver , amount)) {
							String content = "Successfull";
							sendData = cm.makeCipheredMessage(content, clients.get(number));
						}
						else {
							String content = "Aborted";
							sendData = cm.makeCipheredMessage(content, clients.get(number));
						}
					}
					else {
						String content = "Aborted";
						sendData = cm.makeCipheredMessage(content, clients.get(number));
					}	
					
					
						
					break;
				case "charge":
					break;
				case "check":
	            	checkBalance(Integer.valueOf(number));
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


	
	
	

