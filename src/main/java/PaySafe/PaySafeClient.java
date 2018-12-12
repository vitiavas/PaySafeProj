package PaySafe;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import org.bouncycastle.util.Arrays;

import Crypto.Constants;
import Crypto.CryptoManager;
import Crypto.CryptoUtil;
import PaySafeBank.BankServer;

public class PaySafeClient {

	private static final String ALICE_NUMBER = "910984085";
    private static final String CHARLIE_NUMBER = "913330533";
    private static final String BOB_NUMBER = "964512431";
    private Certificate serverCer;
    private DatagramSocket socket;
    private InetAddress address;
    private long readID =0;
    private long writeTimestamp = -1;
    private CryptoManager cm;
 
    public PaySafeClient(String name) throws UnrecoverableKeyException, KeyStoreException, CertificateException, IOException {
    	
    	PrivateKey privateKey = CryptoUtil.getPrivateKeyFromKeyStoreResource(Constants.KEYSTORE_CLIENTS + name + ".jks", 
    			Constants.PASSWORD.toCharArray(), name, Constants.PASSWORD.toCharArray());
    	Certificate c = CryptoUtil.getX509CertificateFromResource(Constants.CLIENTS_FOLDER + name + ".cer");
    	if(name.equals(Constants.ALICE))
    		cm = new CryptoManager(c.getPublicKey(), privateKey, ALICE_NUMBER);
    	else if (name.equals(Constants.BOB))
    		cm = new CryptoManager(c.getPublicKey(), privateKey, BOB_NUMBER);
    	else
    		cm = new CryptoManager(c.getPublicKey(), privateKey, CHARLIE_NUMBER);
        socket = new DatagramSocket();
        address = InetAddress.getByName(Constants.LOCALHOST);
        serverCer = CryptoUtil.getX509CertificateFromResource(Constants.CLIENTS_FOLDER + Constants.SERVER_CERTIFICATE);
    }
 
    public String sendMessageUDP(int receiverNumber, double amount, String operation) throws IOException, CertificateException, NoSuchProviderException {
    	String msg = null;
    	// CHECK BALANCE
    	if(amount == -1) {
        	msg = operation + " " + receiverNumber + " ";
    	// PAYMENT
    	} else {
        	msg = operation + " " + receiverNumber + " " + amount + " ";    		
    	}
    	if(operation.equals(Constants.PAY_OPERATION)) {
    		writeTimestamp++;
    		msg += writeTimestamp;
		}
    	else {
    		readID++;
    		msg += readID;
    	}
    	System.out.println("ecnrypting message: " + msg);
    	
        byte[] buf = cm.makeCipheredMessage(msg, serverCer.getPublicKey());
        DatagramPacket packet = new DatagramPacket(buf, buf.length, address, 6666);
        socket.send(packet);
        
        packet = new DatagramPacket(buf, buf.length);
        socket.receive(packet);
		System.out.println("Received response!");
		
		byte[] messageInBytes = Arrays.copyOfRange(packet.getData(), 0, packet.getLength());
		
		byte[] numberReceived = Arrays.copyOfRange(messageInBytes, 0, 9);
		byte[] cipheredMessage = Arrays.copyOfRange(messageInBytes, 9, messageInBytes.length);
		byte[] decipheredMessage = cm.decipherCipheredMessage(cipheredMessage, serverCer.getPublicKey());
		
		String received = new String(decipheredMessage);
        return received;
    }
 
    public void close() {
        socket.close();
    }
    
}
