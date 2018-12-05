package PaySafe;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import Crypto.CryptoManager;
import Crypto.CryptoUtil;

public class PaySafeClient {

    private static final String KEYSTORE = "clients/";
    private static final String PASSWORD = "123456";
	
	private static final String ALICE_NUMBER = "910984085";
    private static final String SERVER_NUMBER = "964089137";
    private static final String CHARLIE_NUMBER = "913330533";
    private static final String BOB_NUMBER = "964512431";
    private static final String CER = "clients/";
    private DatagramSocket socket;
    private InetAddress address;
    private long readID =0;
    private long writeTimestamp = -1;
    private String name;
    private CryptoManager cm;
 
    private byte[] buf;
 
    public PaySafeClient(String name) throws UnrecoverableKeyException, KeyStoreException, CertificateException, IOException {
    	
    	PrivateKey privateKey = CryptoUtil.getPrivateKeyFromKeyStoreResource(KEYSTORE+name+".jks", PASSWORD.toCharArray(), name, PASSWORD.toCharArray());
    	Certificate c = CryptoUtil.getX509CertificateFromResource(CER+ name + ".cer");
    	if(name.equals("Alice"))
    		cm = new CryptoManager(c.getPublicKey(), privateKey,ALICE_NUMBER);
    	else if (name.equals("Bob"))
    		cm = new CryptoManager(c.getPublicKey(), privateKey,BOB_NUMBER);
    	else
    		cm = new CryptoManager(c.getPublicKey(), privateKey,CHARLIE_NUMBER);
        socket = new DatagramSocket();
        address = InetAddress.getByName("localhost");
        this.name = name;
    }
 
    public String sendMessageUDP(String msg, String r) throws IOException {
    	
    	if(r.equals("pay") || r.equals("check")) {
    		writeTimestamp++;
    		msg += writeTimestamp;
		}
    	else {
    		readID++;
    		msg += readID;
    	}
    	
        buf = msg.getBytes();
        DatagramPacket packet = new DatagramPacket(buf, buf.length, address, 6666);
        socket.send(packet);
        
        packet = new DatagramPacket(buf, buf.length);
        socket.receive(packet);
        String received = new String(packet.getData(), 0, packet.getLength());
        return received;
    }
 
    public void close() {
        socket.close();
    }
    
}
