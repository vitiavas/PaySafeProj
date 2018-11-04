package Application;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;

@RestController
@RequestMapping("dashboard")
public class PaySafeController {


    public static final String ACCOUNT_SID = System.getenv("TWILIO_ACCOUNT_SID");
    public static final String AUTH_TOKEN = System.getenv("TWILIO_AUTH_TOKEN");
    
    @RequestMapping(value = "/test", method = RequestMethod.GET)
    public void test() {
    	System.out.println("TEST");
    }
    
    @RequestMapping("sendMessage")
    public void sendMessage(@RequestParam(value = "senderNumber") String senderNumber,
			@RequestParam(value = "receiverNumber") String receiverNumber,
			@RequestParam(value = "amount") String amount) {
    	
    	// TYPE CODE HERE
    	
    	Twilio.init(ACCOUNT_SID, AUTH_TOKEN);
    	Message message = Message.creator(
    				new PhoneNumber(senderNumber), 
    				new PhoneNumber(receiverNumber),
    				"This is automatic message with money: " + amount).create();
    	
    }
}
