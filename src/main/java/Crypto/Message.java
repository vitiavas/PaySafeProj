package Crypto;

import java.io.Serializable;
import java.security.PublicKey;


public class Message implements Serializable{

    /**
	 * 
	 */
	private static final long serialVersionUID = 1252380591417580088L;

	private double amount;
    private int sender;
    private int destination;
    private int timeStamp;
    private PublicKey senderK;
    
    public Message(PublicKey sender) {
        this.senderK = sender;
    }
    
    public Message(int sender, int receiver, double amount, int timeStamp) {
        this.sender = sender;
        this.destination=receiver;
        this.amount=amount;
        this.timeStamp=timeStamp;
    }

    public double getAmount() {
        return amount;
    }

    public int getSender() {
        return sender;
    }

    public int getDestination() {
		return destination;
    }
    
    public PublicKey getSenderK() {
    	return senderK;
    }


    @Override
    public String toString() {
        return amount + " from " + sender;
    }

    public int getTimestamp() {
        return timeStamp;
    }

}
