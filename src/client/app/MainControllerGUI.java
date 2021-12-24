package client.app;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.util.HashMap;

import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

import org.bouncycastle.crypto.tls.BasicTlsPSKIdentity;
import org.bouncycastle.crypto.tls.TlsClient;
import org.bouncycastle.crypto.tls.TlsClientProtocol;

import client.app.crypto.CryptographicOperations;
import client.app.httpInterface.HTTPSpskClient;
import client.app.httpInterface.HttpClientAuthenticationAuthorization;
import client.app.util.Constants;

public class MainControllerGUI extends JFrame {

	private static final SecureRandom secureRandom = new SecureRandom();
	
	private static String resName;
	private static String subType;
	private static HashMap<String, String> aeTargets = new HashMap<String, String>();
	
	// Define all the components as global private variables
	private static JLabel resLabel;
	private static JComboBox<String> resource;
	private static JLabel subLabel;
	private static JComboBox<String> subscription;
	
	private static JButton regButton;
	
	private static JButton getTempButton;
	private static JButton getHumButton;
	private static JButton getLoudButton;
	private static JTextField textTemp;
	private static JTextField textHum;
	private static JTextField textLoud;
	private static JLabel tempUnit;
	private static JLabel humUnit;
	private static JLabel loudUnit;
	
	private static JLabel respMsg;
	
	public MainControllerGUI() throws IOException {
		setTitle("Client Application");
        setSize(1000, 500);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        
        setLayout(new GridBagLayout());
        
        resLabel = new JLabel("Choose the resource that you want to retrieve");
        resource = new JComboBox<String>();
        resource.addItem("temperature");
        resource.addItem("humidity");
        resource.addItem("loudness");
        
        subLabel = new JLabel("Choose the type of subscription");
        subscription = new JComboBox<String>();
        subscription.addItem("silver");
        subscription.addItem("gold");
        subscription.addItem("platinum");
        
        regButton = new JButton("Register");
        
        regButton.addActionListener(new ActionListener() {
        	 @Override
             public void actionPerformed(ActionEvent evt) {
        		 new Thread(){
        			 public void run(){
        				 resName = (String) resource.getSelectedItem();
        				 subType = (String) subscription.getSelectedItem();

        				 String[] response = HttpClientAuthenticationAuthorization.resourceRegistration(resName, subType).split("\\|");
        				 String msg = response[0];
        				 String err = response[1];
        				 
        				 if(err.equals("false")) {
        					 String symmetricSessionKey = HttpClientAuthenticationAuthorization.sendAuthenticationAndAuthorizationRequest();
        					 
        					 
        					 // Create the HTTPS client to send encrypted requests to the OM2M Infrastructure Node
        					 BasicTlsPSKIdentity pskIdentity = new BasicTlsPSKIdentity(Constants.clientID, symmetricSessionKey.getBytes());
        					 HTTPSpskClient httpsClient = new HTTPSpskClient(null, pskIdentity);
        					 InetAddress address;
        					 int port = 5556;
        					 try {
        						 address = InetAddress.getLocalHost();
        						 TlsClientProtocol protocol = openTlsConnection(address, port, httpsClient);
        						 httpsClient.createAEclient(protocol);
        					 } catch (UnknownHostException e) {
        						 // TODO Auto-generated catch block
        						 e.printStackTrace();
        					 } catch (IOException e) {
        						 // TODO Auto-generated catch block
        						 e.printStackTrace();
        					 }

        					 // Save the target of the application entity corresponding to the specific resource
        					 aeTargets.put(resName, HttpClientAuthenticationAuthorization.getAeTarget());
        					 
        					 if(msg.equals("empty")) {
        						 System.out.println("Hello\n");
        						 respMsg.setVisible(false);
        					 }else {
        						 System.out.println("Hello1\n");
        						 respMsg.setText(msg);
        						 respMsg.setVisible(true);
        					 }

        					 if(resName.equals(Constants.TEMPERATURE)) {
        						 getTempButton.setEnabled(true);
        					 }else if(resName.equals(Constants.HUMIDITY)) {
        						 getHumButton.setEnabled(true);
        					 }else if(resName.equals(Constants.LOUDNESS)) {
        						 getLoudButton.setEnabled(true);
        					 }
        				 }else {
        					 System.out.println("Hello2\n");
        					 respMsg.setText(msg);
        					 respMsg.setVisible(true);
        				 }
        				 
        			 }
        		 }.start();
        	 }
        });
        
        getTempButton = new JButton("Retrieve temperature");
        getTempButton.setEnabled(false);
        getTempButton.addActionListener(new ActionListener() {
        	@Override
        	public void actionPerformed(ActionEvent evt) {
        		new Thread(){
        			public void run(){
        				String response = null;
        				String symmetricSessionKey = CryptographicOperations.getSymmetricSessionKey();
        				String cinTarget = aeTargets.get(Constants.TEMPERATURE) + 
        						"/" + Constants.TEMPERATURE.toUpperCase() + "/la";
        				// Create the HTTPS client to send encrypted requests to the OM2M Infrastructure Node
        				BasicTlsPSKIdentity pskIdentity = new BasicTlsPSKIdentity(Constants.clientID, symmetricSessionKey.getBytes());
        				HTTPSpskClient httpsClient = new HTTPSpskClient(null, pskIdentity);
        				InetAddress address;
        				int port = 5556;
        				try {
        					address = InetAddress.getLocalHost();
        					TlsClientProtocol protocol = openTlsConnection(address, port, httpsClient);
        					response = httpsClient.retrieveLatestResource(protocol, cinTarget);
        				} catch (UnknownHostException e) {
        					// TODO Auto-generated catch block
        					e.printStackTrace();
        				} catch (IOException e) {
        					// TODO Auto-generated catch block
        					e.printStackTrace();
        				}
        				
        				if(response.length() <= 10) {
        					textTemp.setText(response);
        				}
        			}
        		}.start();
        	}
        });
        
        getHumButton = new JButton("Retrieve humidity");
        getHumButton.setEnabled(false);
        getHumButton.addActionListener(new ActionListener() {
        	@Override
        	public void actionPerformed(ActionEvent evt) {
        		new Thread(){
        			public void run(){
        				String response = null;
        				String symmetricSessionKey = CryptographicOperations.getSymmetricSessionKey();
        				String cinTarget = aeTargets.get(Constants.HUMIDITY) + 
        						"/" + Constants.HUMIDITY.toUpperCase() + "/la";
        				// Create the HTTPS client to send encrypted requests to the OM2M Infrastructure Node
        				BasicTlsPSKIdentity pskIdentity = new BasicTlsPSKIdentity(Constants.clientID, symmetricSessionKey.getBytes());
        				HTTPSpskClient httpsClient = new HTTPSpskClient(null, pskIdentity);
        				InetAddress address;
        				int port = 5556;
        				try {
        					address = InetAddress.getLocalHost();
        					TlsClientProtocol protocol = openTlsConnection(address, port, httpsClient);
        					response = httpsClient.retrieveLatestResource(protocol, cinTarget);
        				} catch (UnknownHostException e) {
        					// TODO Auto-generated catch block
        					e.printStackTrace();
        				} catch (IOException e) {
        					// TODO Auto-generated catch block
        					e.printStackTrace();
        				}
        				
        				if(response.length() <= 10) {
        					textHum.setText(response);
        				}
        			}
        		}.start();
        	}
        });
        
        getLoudButton = new JButton("Retrieve loudness");
        getLoudButton.setEnabled(false);
        getLoudButton.addActionListener(new ActionListener() {
        	@Override
        	public void actionPerformed(ActionEvent evt) {
        		new Thread(){
        			public void run(){
        				String response = null;
        				String symmetricSessionKey = CryptographicOperations.getSymmetricSessionKey();
        				String cinTarget = aeTargets.get(Constants.LOUDNESS) + 
        						"/" + Constants.LOUDNESS.toUpperCase() + "/la";
        				// Create the HTTPS client to send encrypted requests to the OM2M Infrastructure Node
        				BasicTlsPSKIdentity pskIdentity = new BasicTlsPSKIdentity(Constants.clientID, symmetricSessionKey.getBytes());
        				HTTPSpskClient httpsClient = new HTTPSpskClient(null, pskIdentity);
        				InetAddress address;
        				int port = 5556;
        				try {
        					address = InetAddress.getLocalHost();
        					TlsClientProtocol protocol = openTlsConnection(address, port, httpsClient);
        					response = httpsClient.retrieveLatestResource(protocol, cinTarget);
        				} catch (UnknownHostException e) {
        					// TODO Auto-generated catch block
        					e.printStackTrace();
        				} catch (IOException e) {
        					// TODO Auto-generated catch block
        					e.printStackTrace();
        				}
        				
        				if(response.length() <= 10) {
        					textLoud.setText(response);
        				}
        			}
        		}.start();
        	}
        });
        
        textTemp = new JTextField(10);
        textTemp.setEditable(false);
        textHum = new JTextField(10);
        textHum.setEditable(false);
        textLoud = new JTextField(10);
        textLoud.setEditable(false);
        
        tempUnit = new JLabel("ºC");
        humUnit = new JLabel("RH");
        loudUnit = new JLabel("dB");
        
        respMsg = new JLabel();
        respMsg.setForeground(Color.RED);
        
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new Insets(10, 0, 10, 0);
        add(resLabel, gbc);
        
        gbc.gridx = 0;
        gbc.gridy = 1;
        add(resource, gbc);
        
        gbc.gridx = 3;
        gbc.gridy = 2;
        add(regButton, gbc);
        
        gbc.gridx = 0;
        gbc.gridy = 3;
        add(subLabel, gbc);
        
        gbc.gridx = 0;
        gbc.gridy = 4;
        add(subscription, gbc);    
        
        gbc.gridx = 0;
        gbc.gridy = 5;
        add(respMsg, gbc);
        
        gbc.gridx = 0;
        gbc.gridy = 6;
        gbc.insets = new Insets(5, 10, 5, 10);
        add(getTempButton, gbc);
        gbc.gridx = 1;
        gbc.gridy = 6;
        add(textTemp, gbc);
        gbc.gridx = 2;
        gbc.gridy = 6;
        add(tempUnit, gbc);
        gbc.gridx = 0;
        gbc.gridy = 7;
        add(getHumButton, gbc);
        gbc.gridx = 1;
        gbc.gridy = 7;
        add(textHum, gbc);
        gbc.gridx = 2;
        gbc.gridy = 7;
        add(humUnit, gbc);
        gbc.gridx = 0;
        gbc.gridy = 8;
        add(getLoudButton, gbc);
        gbc.gridx = 1;
        gbc.gridy = 8;
        add(textLoud, gbc);
        gbc.gridx = 2;
        gbc.gridy = 8;
        add(loudUnit, gbc);
        
        pack();
        setVisible(true);
        
	}
	
	public static TlsClientProtocol openTlsConnection(InetAddress address, int port, TlsClient client) throws IOException {
        Socket s = new Socket(address, port);
        TlsClientProtocol protocol = new TlsClientProtocol(s.getInputStream(), s.getOutputStream(), secureRandom);
        protocol.connect(client);
        return protocol;
    }
	
	public static void main(String[] args) throws IOException {

		HttpClientAuthenticationAuthorization.ECQVregistration();
		
		new MainControllerGUI();
		
	}

}
