package client.app.httpInterface;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintStream;
import java.io.PrintWriter;

import java.util.Hashtable;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.PSKTlsClient;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.ServerOnlyTlsAuthentication;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.TlsExtensionsUtils;
import org.bouncycastle.crypto.tls.TlsPSKIdentity;
import org.bouncycastle.crypto.tls.TlsSession;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

import client.app.util.Constants;

public class HTTPSpskClient extends PSKTlsClient{
	
	TlsSession session;
	
	public HTTPSpskClient(TlsSession session, TlsPSKIdentity id) {
		super(id);
		this.session = session;
	}
	
	public TlsSession getSessionToResume() {
        return this.session;
    }
	
	public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Exception cause) {
		PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
		out.println("TLS client raised alert (AlertLevel." + alertLevel + ", AlertDescription." + alertDescription + ")");
		if (message != null) {
			out.println(message);
		}
		if (cause != null) {
			cause.printStackTrace(out);
		}
	}

	public void notifyAlertReceived(short alertLevel, short alertDescription) {
		PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
		out.println("TLS client received alert (AlertLevel." + alertLevel + ", AlertDescription."
				+ alertDescription + ")");
	}
	
	public void notifyHandshakeComplete() throws IOException {
        super.notifyHandshakeComplete();
        TlsSession newSession = context.getResumableSession();	        
        if (newSession != null) {
            byte[] newSessionID = newSession.getSessionID();
            String hex = Hex.toHexString(newSessionID);

            if (this.session != null && Arrays.areEqual(this.session.getSessionID(), newSessionID)) {
                System.out.println("Resumed session: " + hex);
            }else {
                System.out.println("Established session: " + hex);
            }
            this.session = newSession;
        }
    }
	
	public int[] getCipherSuites() {
        return new int[]{ CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
            CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384, CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
            CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA };
		//return new int[]{ CipherSuite.TLS_PSK_WITH_AES_256_CCM_8};
    }
	
	public ProtocolVersion getMinimumVersion() {
        return ProtocolVersion.TLSv12;
    }
	
	public Hashtable getClientExtensions() throws IOException {
        Hashtable clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(super.getClientExtensions());
        TlsExtensionsUtils.addEncryptThenMACExtension(clientExtensions);
        return clientExtensions;
    }
	
	public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException {
        super.notifyServerVersion(serverVersion);
        System.out.println("TLS-PSK client negotiated " + serverVersion);
    }

    public TlsAuthentication getAuthentication() throws IOException {
        return new ServerOnlyTlsAuthentication() {
            public void notifyServerCertificate(org.bouncycastle.crypto.tls.Certificate serverCertificate) 
            		throws IOException {
                Certificate[] chain = serverCertificate.getCertificateList();
                System.out.println("TLS-PSK client received server certificate chain of length " + chain.length);
                for (int i = 0; i != chain.length; i++) {
                    Certificate entry = chain[i];
                    // TODO Create fingerprint based on certificate signature algorithm digest
                    System.out.println("Subject of the certificate: " + entry.getSubject());
                }
            }
        };
    }
	
	public void createAEclient(TlsClientProtocol protocol) throws IOException {

        OutputStream output = protocol.getOutputStream();
        PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(output));
        
        /* Create the json body for the request */
		JsonObject jsonBody = new JsonObject();
		jsonBody.addProperty("method", Constants.CREATE);
		jsonBody.addProperty("origin", Constants.clientID);
		jsonBody.addProperty("resource", Constants.AE);
		Gson gson = new GsonBuilder().create();
		String body = gson.toJson(jsonBody);
		
        // Write data
		printWriter.println(body);
		printWriter.flush();

        InputStream input = protocol.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(input));

        String line;
        if ((line = reader.readLine()) != null) {
            System.out.println(">>> " + line);
        }
	}
	
	public String retrieveLatestResource(TlsClientProtocol protocol, String target) throws IOException {
		
		OutputStream output = protocol.getOutputStream();
        PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(output));
        
        /* Create the json body for the request */
		JsonObject jsonBody = new JsonObject();
		jsonBody.addProperty("method", Constants.RETRIEVE);
		jsonBody.addProperty("target", target);
		jsonBody.addProperty("origin", Constants.clientID);
		Gson gson = new GsonBuilder().create();
		String body = gson.toJson(jsonBody);
		
		// Write data
		printWriter.println(body);
		printWriter.flush();

		InputStream input = protocol.getInputStream();
		BufferedReader reader = new BufferedReader(new InputStreamReader(input));

		String line;
		if ((line = reader.readLine()) != null) {
			System.out.println(">>> " + line);
		}
		return line;
	}
}
