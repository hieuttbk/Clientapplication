package client.app.util;

public class Constants {

	// Client identifier (32 characters)
	public static final String clientID = "95827ab482d7f0e26415f8ebb352dac9";
	
	// Fix the size of the random numbers used in the algorithm
	public static final int randomNumberSize = 32;
	
	// Fix the size of the nonce used for AES_CCM
	public static final int nonceSize = 12;
	
	// Permitted resource names
	public static final String TEMPERATURE = "temperature";
	public static final String HUMIDITY = "humidity";
	public static final String LOUDNESS = "loudness";
	
	// Subscription type
	public static final String SILVER = "silver";
	public static final String GOLD = "gold";
	public static final String PLATINUM = "platinum";
	
	// Cost of different subscriptions
	public static final int SILVER_COST = 10;
	public static final int GOLD_COST = 100;
	public static final int PLATINUM_COST = 500;
	
	// Duration period of different subscriptions
	public static final String SILVER_PERIOD = "30";
	public static final String GOLD_PERIOD = "365";
	public static final String PLATINUM_PERIOD = "1825";
	
	// The methods used to retrieve resources from the OM2M server
	public static final String CREATE = "CREATE";
	public static final String RETRIEVE = "RETRIEVE";
	//public static final String DISCOVERY = "DISCOVERY";
	
	// The only resource that the client should be able to create is the application entity
	public static final String AE = "AE";
}
