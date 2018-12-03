package PaySafe;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

public class PaySafeClient {

	private static final int ALICE_NUMBER = 910984085;
    private static final int SERVER_NUMBER = 964089137;
    private static final int CHARLIE_NUMBER = 913330533;
    private static final int BOB_NUMBER = 964512431;
    private DatagramSocket socket;
    private InetAddress address;
 
    private byte[] buf;
 
    public PaySafeClient() throws SocketException, UnknownHostException {
        socket = new DatagramSocket();
        address = InetAddress.getByName("localhost");
    }
 
    public String sendMessageUDP(String msg) throws IOException {
    	
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
