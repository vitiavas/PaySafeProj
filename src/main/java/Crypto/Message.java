package Crypto;

import java.io.Serializable;


public class Message implements Serializable{

    /**
	 * 
	 */
	private static final long serialVersionUID = 1252380591417580088L;

	private double amount;
    private int sender;
    private int destination;
    private int timeStamp;
    
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

    public int getTimestamp() {
        return timeStamp;
    }

}
