package client.app.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Scanner;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.math.ec.ECPoint;

import client.app.MainControllerGUI;
import client.app.util.Constants;

public class CryptographicOperations {

	private static ECPrivateKeyParameters privateKey;
	private static ECPublicKeyParameters publicKey;
	private static ECPublicKeyParameters publicKeyDAS;
	private static byte[] ECQVRandom;
	private static byte[] resRegRandom;
	private static byte[] resRegRandomZ;
	private static byte[] symmetricSessionKey;
	public static long star_6_1;
	public static long time5_9;
	public static long time7_8;
	public static long time5_1to5_11;
	public static ECPoint pointU;

	// private static String resName = null;

	/* Transform a byte array in an hexadecimal string */
	private static String toHex(byte[] data) {
		StringBuilder sb = new StringBuilder();
		for (byte b : data) {
			sb.append(String.format("%02x", b & 0xff));
		}
		return sb.toString();
	}

	/*
	 * Transform an hexadecimal string in byte array (It works if the string only
	 * contains the hexadecimal characters)
	 */
	private static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	/* Convert a string representation in its hexadecimal string */
	private static String toHex(String arg) {
		return String.format("%02x", new BigInteger(1, arg.getBytes()));
	}

	/* Convert long to byte array */
	private static byte[] longToByteArray(long value) {
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(value);
		return buffer.array();

	}

	/* Concatenation of two byte arrays */
	private static byte[] concatByteArrays(byte[] a, byte[] b) {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		try {
			outputStream.write(a);
			outputStream.write(b);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte[] concatResult = outputStream.toByteArray();
		return concatResult;
	}

	/* Perform SHA256 and return the result */
	private static byte[] sha256(byte[] data) {
		SHA256Digest digest = new SHA256Digest();
		byte[] hash = new byte[digest.getDigestSize()];
		digest.update(data, 0, data.length);
		digest.doFinal(hash, 0);
		return hash;
	}

	/* Return an encoded elliptic curve point obtained as U = uG */
	public static String getUfromRandom() {
		DateFormat dateFormat2 = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss:SSS");
		Date date2 = new Date();
		System.out.println("***************time start 5.2 BUGGG****************"+dateFormat2.format(date2));
		// Get domain parameters for example curve secp256r1

		System.out.println("\n >>>>>>> Process 5.1, 5.2 created u,U=u.G .....");
		long time = System.nanoTime();
		X9ECParameters ecp = SECNamedCurves.getByName("secp256r1");
		ECDomainParameters domainParams = new ECDomainParameters(ecp.getCurve(), ecp.getG(), ecp.getN(), ecp.getH(),
				ecp.getSeed());
		/* Generate a random number with a fixed size of 32 bytes */
		SecureRandom random = new SecureRandom();
		ECQVRandom = new byte[Constants.randomNumberSize];
		random.nextBytes(ECQVRandom); // Fill the array with random bytes
		System.out.println("u = " + toHex(ECQVRandom));

		/* Elliptic curve multiplication using the random number */
		long multi;
		long endmulti;
		float total = 0;
	
//		for (int i = 0; i < 100; i++) {
			multi = System.nanoTime();
			pointU = domainParams.getG().multiply(new BigInteger(ECQVRandom));
			endmulti = System.nanoTime();
//			if(i!=0)
//			total+=(endmulti-multi);
//		}
//		System.out.println("******star_multi5_4: " + total/99);
	
		byte[] encodedU = pointU.getEncoded(true);
		System.out.println("U = " + toHex(encodedU));
		System.out.println("***************time end 5.2****************"+System.nanoTime());
		DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss:SSS");
		Date date = new Date();
		System.out.println("***************time end 5.2 BUGGG****************"+dateFormat.format(date));
		
		System.out.println("***************time process 5.1 to 5.2***************"+ (System.nanoTime()-time));
		return toHex(encodedU);
	}

	/*
	 * Generate the public and private keys of the client using information received
	 * from the dynamic authorization server
	 */
	public static void generateECKeyPair(String cert, String q) {
		System.out.println("\n >>>>>>> Process 5.9 to 5.10 created du,Pu .....");
		// Get domain parameters for example curve secp256r1
		DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss:SSS");
		Date date = new Date();
		System.out.println("***************time start 5.9 BUGGG****************"+dateFormat.format(date));
		time5_9=System.nanoTime();
		System.out.println("***************timestamp start 5.9****************"+time5_9);
		X9ECParameters ecp = SECNamedCurves.getByName("secp256r1");
		ECDomainParameters domainParams = new ECDomainParameters(ecp.getCurve(), ecp.getG(), ecp.getN(), ecp.getH(),
				ecp.getSeed());
		byte[] certBytes = hexStringToByteArray(cert);
		BigInteger qBigInt = new BigInteger(hexStringToByteArray(q));

		/*
		 * Calculation of the private key as d = H(cert||ID)u + q and public key as P =
		 * dG
		 */
		System.out.println("\n >>>>>>> Process 5.9 created du = H(cert_u||IDu)u+qu .....");
		/* Concatenation of 2 bytes array */
		byte[] certIDconcat = concatByteArrays(certBytes, hexStringToByteArray(Constants.clientID));

		/* Do the sha256 of the certIDconcat byte array */
		long multi = System.nanoTime();
		byte[] hash = sha256(certIDconcat);
		System.out.println("****************SHA256_5_9: " + (System.nanoTime() - multi));

		/* Multiply for the random value u */
		BigInteger bigIntHash = new BigInteger(hash);
		multi = System.nanoTime();
		BigInteger hashRandMult = bigIntHash.multiply(new BigInteger(ECQVRandom));
		System.out.println("****************star_multi5_9: " + (System.nanoTime() - multi));

		/* Sum for the q value to obtain the private key */
		multi = System.nanoTime();
		BigInteger privKey = hashRandMult.add(qBigInt);
		System.out.println("****************star_add5_9: " + (System.nanoTime() - multi));
		privateKey = new ECPrivateKeyParameters(privKey, domainParams);

		/*
		 * Perform elliptic curve multiplication operation to obtain the public key from
		 * the private key
		 */
		System.out.println("\n >>>>>>> Process 5.10 created Pu=du*G .....");
		multi = System.nanoTime();
		ECPoint pubKeyPoint = domainParams.getG().multiply(privateKey.getD());
		System.out.println("****************star_multi5_10: " + (System.nanoTime() - multi));
		publicKey = new ECPublicKeyParameters(pubKeyPoint, domainParams);

		System.out.println("Private key: " + toHex(privateKey.getD().toByteArray()));
		System.out.println("Public key: " + toHex(publicKey.getQ().getEncoded(true)));
	}

	/*
	 * Check if the information received from the dynamic authorization server has
	 * not been tampered
	 */
	public static boolean verifyPublicKey(String encodedStringCert, String encodedStringPubKeyDAS) {
		System.out.println("\n >>>>>>> Process 5.11 verify Pu .....");
		// Get domain parameters for example curve secp256r1
		X9ECParameters ecp = SECNamedCurves.getByName("secp256r1");
		ECDomainParameters domainParams = new ECDomainParameters(ecp.getCurve(), ecp.getG(), ecp.getN(), ecp.getH(),
				ecp.getSeed());
		byte[] encodedCert = hexStringToByteArray(encodedStringCert);
		/* Decode the certificate to obtain its elliptic curve point representation */
		ECPoint cert = ecp.getCurve().decodePoint(encodedCert);

		byte[] encodedPubKeyDAS = hexStringToByteArray(encodedStringPubKeyDAS);
		/*
		 * Decode the public key of the dynamic authorization server to obtain its point
		 * representation in the elliptic curve
		 */
		ECPoint pubKeyDASpoint = ecp.getCurve().decodePoint(encodedPubKeyDAS);
		publicKeyDAS = new ECPublicKeyParameters(pubKeyDASpoint, domainParams);
		System.out.println("Public key of DAS server: " + toHex(publicKeyDAS.getQ().getEncoded(true)));

		/* Compute the public key using H(cert||ID)cert + P_DAS */
		/* Concatenation of 2 bytes array */
		byte[] certIDconcat = concatByteArrays(encodedCert, hexStringToByteArray(Constants.clientID));

		/* Do the sha256 of the certIDconcat byte array */
		long multi = System.nanoTime();
		byte[] hash = sha256(certIDconcat);
		System.out.println("****************SHA256_5_11: " + (System.nanoTime() - multi));
		BigInteger bigIntHash = new BigInteger(hash);

		/* Elliptic curve point multiplication */
		multi = System.nanoTime();
		ECPoint intermPoint = cert.multiply(bigIntHash);
		System.out.println("****************star_multi5_11: " + (System.nanoTime() - multi));
		/*
		 * Sum intermPoint to the public key point of the dynamic authorization server
		 * to obtain the public key point of the client
		 */
		multi = System.nanoTime();
		ECPoint pubKeyPoint = intermPoint.add(pubKeyDASpoint);
		System.out.println("****************star_add5_11: " + (System.nanoTime() - multi));
		System.out.println("*****************time process 5.9 to 5.11*************"+(System.nanoTime()-time5_9));
        time5_1to5_11=(System.nanoTime()-MainControllerGUI.time);
		if (pubKeyPoint.equals(publicKey.getQ())) {
			return true;
		} else {
			return false;
		}
	}

	public static String generateResourceRegistraionMaterial(String resName, String typeSub) {
		boolean inputAccepted = false;
		System.out.println("\n >>>>>>> Process 6.1 to 6.6 created c,z,Z,Tr,Kr,Kz,Sub .....");
		X9ECParameters ecp = SECNamedCurves.getByName("secp256r1");
		ECDomainParameters domainParams = new ECDomainParameters(ecp.getCurve(), ecp.getG(), ecp.getN(), ecp.getH(),
				ecp.getSeed());
		System.out.println("\n >>>>>>> Process 6.1 created c,z .....");
		/* Generate a random number with a fixed size of 32 bytes */
		star_6_1 = System.nanoTime();
		SecureRandom random = new SecureRandom();
		resRegRandom = new byte[Constants.randomNumberSize];
		random.nextBytes(resRegRandom); // Fill the array with random bytes
		System.out.println("c = " + toHex(resRegRandom));

		resRegRandomZ = new byte[Constants.randomNumberSize];
		random.nextBytes(resRegRandomZ); // Fill the array with random bytes
		System.out.println("z = " + toHex(resRegRandomZ));

		System.out.println("\n >>>>>>> Process 6.2 created Z=z.G .....");
		long multi = System.nanoTime();
		ECPoint pointZ = domainParams.getG().multiply(new BigInteger(resRegRandomZ));
		System.out.println("****************star_multi6_2: " + (System.nanoTime() - multi));
		byte[] encodeZ = pointZ.getEncoded(true);
		System.out.println("Z = " + toHex(encodeZ));

		System.out.println("\n >>>>>>> Process 6.3 created Tr .....");
		/* Generate a timestamp */
		Date date = new Date();
		long regTimestamp = date.getTime();
		byte[] regTimestampBytes = longToByteArray(regTimestamp);

		/*
		 * Compute the key Kr = H(d*P_DAS||Tr) used to encrypt requested resource (It is
		 * done for privacy purposes)
		 */
		/* Elliptic curve multiplication */
		System.out.println("\n >>>>>>> Process 6.4 created Kr = H(d*P_DAS||Tr) .....");
		multi = System.nanoTime();
		ECPoint secretPoint = publicKeyDAS.getQ().multiply(privateKey.getD());
		System.out.println("****************star_multi6_4: " + (System.nanoTime() - multi));
		byte[] encodedSecretPoint = secretPoint.getEncoded(true);

		/* Concatenate the encoded secret point with the timestamp */
		byte[] secretTimestampConcat = concatByteArrays(encodedSecretPoint, regTimestampBytes);

		/* Do the sha256 of the secretTimestampConcat byte array */
		multi = System.nanoTime();
		byte[] Kr = sha256(secretTimestampConcat);
		System.out.println("****************SHA256_6_4: " + (System.nanoTime() - multi));

		System.out.println("Symmetric key Kr: " + toHex(Kr));

		/*
		 * Compute the key Kz = H(z*P_DAS||Tr) used to encrypt requested resource (It is
		 * done for privacy purposes)
		 */
		/* Elliptic curve multiplication */
		System.out.println("\n >>>>>>> Process 6.5 created Kz = H(z*P_DAS||Tr) .....");
		multi = System.nanoTime();
		ECPoint secretPointZ = publicKeyDAS.getQ().multiply(new BigInteger(resRegRandomZ));
		System.out.println("****************star_multi6.5: " + (System.nanoTime() - multi));
		byte[] encodedSecretPointZ = secretPointZ.getEncoded(true);

		/* Concatenate the encoded secret point with the timestamp */
		byte[] secretTimestampConcatZ = concatByteArrays(encodedSecretPointZ, regTimestampBytes);

		/* Do the sha256 of the secretTimestampConcat byte array */
		multi = System.nanoTime();
		byte[] Kz = sha256(secretTimestampConcatZ);
		System.out.println("****************SHA256_6.5: " + (System.nanoTime() - multi));

		System.out.println("Symmetric key Kz: " + toHex(Kz));

		/*
		 * Get resource name and subscription type from the user (it will be change with
		 * a GUI)
		 */
		/*
		 * while(!inputAccepted) { Scanner input = new Scanner(System.in);
		 * System.out.print("Enter the resource that you want to retrieve (" +
		 * Constants.TEMPERATURE + "/" + Constants.HUMIDITY + "/" + Constants.LOUDNESS +
		 * "): "); resName = input.nextLine();
		 * System.out.print("Enter the type of subscription that you prefer [" +
		 * Constants.SILVER + "(" + Constants.SILVER_PERIOD + "-" +
		 * Constants.SILVER_COST + " euro)/" + Constants.GOLD + "(" +
		 * Constants.GOLD_PERIOD + "-" + Constants.GOLD_COST + " euro)/" +
		 * Constants.PLATINUM + "(" + Constants.PLATINUM_PERIOD + "-" +
		 * Constants.PLATINUM_COST + " euro)]: "); typeSub = input.nextLine();
		 * if(!resName.equals(Constants.TEMPERATURE) &&
		 * !resName.equals(Constants.HUMIDITY) && !resName.equals(Constants.LOUDNESS)) {
		 * inputAccepted = false;
		 * System.out.println("Resource name provided is not valid"); }else
		 * if(!typeSub.equals(Constants.SILVER) && !typeSub.equals(Constants.GOLD) &&
		 * !typeSub.equals(Constants.PLATINUM)) { inputAccepted = false;
		 * System.out.println("Type of subscritpion provided is not valid"); }else {
		 * inputAccepted = true; input.close(); } }
		 */

		/* Create the cleartext to encrypt from the information provided by the user */
		System.out.println("\n >>>>>>> Process 6.6 created Sub = E_Kz(Rn||Type||c||IDu||Kr) .....");
		String sepSymb = "||";
		byte[] resNameBytes = hexStringToByteArray(toHex(resName));
		byte[] typeSubBytes = hexStringToByteArray(toHex(typeSub));
		// Add separation symbol to resource name
		byte[] cleartext = concatByteArrays(resNameBytes, hexStringToByteArray(toHex(sepSymb)));
		// Add type of subscription
		cleartext = concatByteArrays(cleartext, typeSubBytes);

		// Add random number

//		cleartext = concatByteArrays(cleartext, hexStringToByteArray(toHex(sepSymb)));
//		cleartext = concatByteArrays(cleartext, resRegRandom);
		String C = toHex(resRegRandom);
		cleartext = concatByteArrays(cleartext, hexStringToByteArray(toHex(sepSymb)));
		cleartext = concatByteArrays(cleartext, hexStringToByteArray(toHex(C)));
		// Add IDu
		cleartext = concatByteArrays(cleartext, hexStringToByteArray(toHex(sepSymb)));
		cleartext = concatByteArrays(cleartext, hexStringToByteArray(toHex(Constants.clientID)));
		// Add Kr
		String KrString = toHex(Kr);
		cleartext = concatByteArrays(cleartext, hexStringToByteArray(toHex(sepSymb)));
		cleartext = concatByteArrays(cleartext, hexStringToByteArray(toHex(KrString)));

		System.out.println("cleartext: " + toHex(cleartext));

		
//	    byte[] nonce4 = hexStringToByteArray("e8f89af90da018b2ff685ffa");
//	    byte[] Kz4 =hexStringToByteArray("29e66566a19a01d53ce4b11add30d87805264325f1cc64c17d3e4fb6472f6fc9");
//	    byte[] cleartext4=hexStringToByteArray("74656d70657261747572657c7c73696c7665727c7c633035303165376563343064363637383862996437399235353035393564376234373162663134643431646362623139633732653536333064323935383032657c7c39353832376162343832643766306532363431356638656262333532646163397c7c34306432653930363638303435386534376232356431373038363164336463346362313932616436353433366162306239643738653233383061623863626630");
////	    byte[] text=new byte[1];
////	    random.nextBytes(text); // Fill the nonce with random bytes
////		System.out.println("nonce = " + toHex(text));
//		CCMBlockCipher ccm1 = new CCMBlockCipher(new AESEngine());
//		ccm1.init(true, new ParametersWithIV(new KeyParameter(Kz4), nonce4));
//		byte[] ciphertext4 = new byte[cleartext4.length + 8];// output buffer
//		int len4 = ccm1.processBytes(cleartext4, 0, cleartext4.length, ciphertext4, 0);// the number of bytes written to out.
//		try {
//			len4 += ccm1.doFinal(ciphertext4, len4);// Add MAC address or verify MAC address
//			// do dai cua MAC la boi so cua 8 va co kich thuoc nho hon ciphertex
//		} catch (IllegalStateException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (InvalidCipherTextException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}

//		System.out.println("========>CLEARTEXT4TOHEX<==========: " + cleartext4);
		// Generate a nonce (12 bytes) to be used for AES_256_CCM_8
		random = new SecureRandom();
		byte[] nonce = new byte[Constants.nonceSize];
		random.nextBytes(nonce); // Fill the nonce with random bytes
		System.out.println("nonce = " + toHex(nonce));

		// Encrypt the cleartext
		multi = System.nanoTime();
		CCMBlockCipher ccm = new CCMBlockCipher(new AESEngine());
		ccm.init(true, new ParametersWithIV(new KeyParameter(Kz), nonce));
		byte[] ciphertext = new byte[cleartext.length + 8];// output buffer
		int len = ccm.processBytes(cleartext, 0, cleartext.length, ciphertext, 0);// the number of bytes written to out.
		try {
			len += ccm.doFinal(ciphertext, len);// Add MAC address or verify MAC address
			// do dai cua MAC la boi so cua 8 va co kich thuoc nho hon ciphertex
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("****************AESCCM_6.6: " +(System.nanoTime()-multi));
		System.out.println("Ciphertext: " + toHex(ciphertext));

		return toHex(regTimestampBytes) + "|" + toHex(ciphertext) + "|" + toHex(nonce) + "|" + toHex(encodeZ) + "|"
				+ toHex(Kr) ;
	}

	public static String createAuthIdentity() {
		System.out.println("\n >>>>>>> Process 7.1 created Qu = H(IDu||c) .....");
		byte[] clientIDBytes = hexStringToByteArray(Constants.clientID);
		// Concatenate the identity with the random number generated during resource
		// registration
		byte[] IDresRegRandomConcat = concatByteArrays(clientIDBytes, resRegRandom);
		// Do the sha256 of the concatenation
		long multi = System.nanoTime();
		byte[] Qu = sha256(IDresRegRandomConcat);
		System.out.println("****************SHA256_7.1: " +(System.nanoTime()-multi));
		System.out.println("C-Client: " + toHex(resRegRandom));
		System.out.println("ClientID(Client): " + Constants.clientID);
		System.out.println("Qu: " + toHex(Qu));

		return toHex(Qu);
	}

	private static String convertHexToString(String hex) {

		StringBuilder sb = new StringBuilder();
		StringBuilder temp = new StringBuilder();

		// 49204c6f7665204a617661 split into two characters 49, 20, 4c...
		for (int i = 0; i < hex.length() - 1; i += 2) {

			// grab the hex in pairs
			String output = hex.substring(i, (i + 2));
			// convert hex to decimal
			int decimal = Integer.parseInt(output, 16);
			// convert the decimal to character
			sb.append((char) decimal);

			temp.append(decimal);
		}

		return sb.toString();
	}

	public static String ticketResigtration(String ET, String Kr, String nonce) {
		System.out.println("\n >>>>>>> Process 6.14 Decrypt ET => Ticket||Texp .....");
		byte[] decodeET = null;
		long multi = System.nanoTime();
		CCMBlockCipher ccm = new CCMBlockCipher(new AESEngine());
		ccm.init(false, new ParametersWithIV(new KeyParameter(hexStringToByteArray(Kr)), hexStringToByteArray(nonce)));
		byte[] tmp = new byte[hexStringToByteArray(ET).length];
		int len = ccm.processBytes(hexStringToByteArray(ET), 0, hexStringToByteArray(ET).length, tmp, 0);
		try {
			len += ccm.doFinal(tmp, len);
			decodeET = new byte[len];
			System.arraycopy(tmp, 0, decodeET, 0, len);
			System.out.println("decodeET: " + toHex(decodeET));
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("****************AESCCM_6_14: " +(System.nanoTime()-multi));
		// int appDataByteLength = decodeET.length;
//		String appData = toHex(decodeET).substring(0, 2 * appDataByteLength); // dang hex co 2 gia tri
//		appData = convertHexToString(appData);
		// String appData = toHex(decodeET); // dang hex co 2 gia tri
		// appData = convertHexToString(appData);
		String appData = convertHexToString(toHex(decodeET));
		System.out.println("dataDecode: " + appData);
		String[] data = appData.split("\\|\\|");

		String ticket = data[0];
		String Texp = data[1];
		System.out.println("Texp: " + Texp);
		System.out.println("Ticket: " + ticket);

		return ticket + "|" + Texp;
	}

	public static String generateSymmetricSessionKey(String Ts) {
		// Compute the symmetric session key SKsession = H(du*Pdas||Ts)
		// Elliptic curve multiplication
		System.out.println("\n >>>>>>> Process 7.8 created Sk .....");
		long multi = System.nanoTime();
		ECPoint secretPoint = publicKeyDAS.getQ().multiply(privateKey.getD());
		System.out.println("****************star_multi7.8: " +(System.nanoTime()-multi));
		byte[] encodedSecretPoint = secretPoint.getEncoded(true);
		// Concatenate encoded secret point with the received timestamp
		byte[] secretTimestampEncoded = concatByteArrays(encodedSecretPoint, hexStringToByteArray(Ts));
		// Do sha256 to obtain the symmetric key
		multi = System.nanoTime();
		symmetricSessionKey = sha256(secretTimestampEncoded);
		System.out.println("****************SHA256_7.8: " +(System.nanoTime()-multi));
		System.out.println("Symmetric session key: " + toHex(symmetricSessionKey));
		return toHex(symmetricSessionKey);
	}

	public static String DecryptURL(String EU, String nonce3, String Sk) {

		// Compute the symmetric session key SKsession = H(du*Pdas||Ts)
		// Elliptic curve multiplication
		
		
		

		byte[] URL = null;
		System.out.println("\n >>>>>>> Process 7.9 Decrypt D_Sk(EU) => URL .....");
		long multi = System.nanoTime();
		CCMBlockCipher ccm = new CCMBlockCipher(new AESEngine());
		ccm.init(false, new ParametersWithIV(new KeyParameter(hexStringToByteArray(Sk)), hexStringToByteArray(nonce3)));
		byte[] tmp = new byte[hexStringToByteArray(EU).length];
		int len = ccm.processBytes(hexStringToByteArray(EU), 0, hexStringToByteArray(EU).length, tmp, 0);
		try {
			len += ccm.doFinal(tmp, len);
			URL = new byte[len];
			System.arraycopy(tmp, 0, URL, 0, len);
			System.out.println("URL: " + convertHexToString(toHex(URL)));
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		long end_7_9 = System.nanoTime();
		System.out.println("****************AESCCM_7.9: " +(System.nanoTime()-multi));
		System.out.println("****************SUM TIME******************: " +(end_7_9-star_6_1+time5_1to5_11));
		return convertHexToString(toHex(URL));
	}

	public static String getSymmetricSessionKey() {
		return toHex(symmetricSessionKey);
	}
}
