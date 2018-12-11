package PaySafeBank;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyStoreException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class Application {
	
	public static void main(String[] args) throws IOException, UnrecoverableKeyException, KeyStoreException, CertificateException {
		
		
		BankServer server = new BankServer();
	    server.start();
	    
	    while(true) {
		    BufferedReader reader =  new BufferedReader(new InputStreamReader(System.in)); 
		    String cmd = reader.readLine(); 
		    if(cmd.equals("exit"))
		    	break;
	    }
	    
	    
    }
    
}
