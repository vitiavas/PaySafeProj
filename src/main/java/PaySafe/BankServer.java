package PaySafe;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
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

public class BankServer {
	public static void main(String[] args) throws IOException, UnrecoverableKeyException, KeyStoreException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException, CertificateException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {

		System.out.println("test");
        BankServer server = new BankServer();
        server.start(6666);
		
	}
    private ServerSocket serverSocket;
    
    public void start(int port) throws IOException {
        serverSocket = new ServerSocket(port);
        while (true)
            new ClientHandler(serverSocket.accept()).start();
    }
 
    public void stop() throws IOException {
        serverSocket.close();
    }

    private static class ClientHandler extends Thread {
        private Socket clientSocket;
        private PrintWriter out;
        private BufferedReader in;
 
        public ClientHandler(Socket socket) {
            this.clientSocket = socket;
        }
        public void run() {
        	try {
				out = new PrintWriter(clientSocket.getOutputStream(), true);
	            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
	            String inputLine;
	            while ((inputLine = in.readLine()) != null) {
	                if (".".equals(inputLine)) {
	                    out.println("bye");
	                    break;
	                }
	                out.println(inputLine);
	            }
	            in.close();
	            out.close();
	            clientSocket.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				
				e.printStackTrace();
			}
        }
    }
}


	
	
	

