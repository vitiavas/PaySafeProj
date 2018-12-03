package PaySafe;

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
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.lang3.StringUtils;

public class BankServer extends Thread{
    private DatagramSocket socket;
    private boolean running;
    private byte[] buf = new byte[256];
    private static final String CHECK_BALANCE = "Check Balance ";
	/**
	 Main function start the bank server on port 6666
	 */
	public static void main(String[] args) throws IOException, UnrecoverableKeyException, KeyStoreException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException, CertificateException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {

        BankServer server = new BankServer();
        server.start();
		
	}

    public BankServer() throws SocketException {
        socket = new DatagramSocket(6666);
    }
    
    public static void checkBalance(int number) {
    	// BALANCE CHECKING PROCESS
    }
    
    
    public void run() {
        running = true;
 
        while (running) {
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            try {
				socket.receive(packet);
	            InetAddress address = packet.getAddress();
	            int port = packet.getPort();
	            packet = new DatagramPacket(buf, buf.length, address, port);
	            String received  = new String(packet.getData(), 0, packet.getLength());
	            
	            if (received.equals("end")) {
	                running = false;
	                continue;
	                
	            } else if(received.contains(CHECK_BALANCE)){
	            	String number = null;
	            	StringUtils.substringAfter(number, CHECK_BALANCE);
	            	checkBalance(Integer.valueOf(number));
	            }
	            socket.send(packet);
			} catch (IOException e) {
				e.printStackTrace();
			}
        }
        socket.close();
    }
}


	
	
	

