package secureLib;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DataBindingException;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.engines.Salsa20Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class CryptoImpl {
	
	public static String asHex (byte buf[]) 
	{
	    StringBuffer strbuf = new StringBuffer(buf.length * 2);
	    int i;
	
	    for (i = 0; i < buf.length; i++) {
	    	if (((int) buf[i] & 0xff) < 0x10)
	    	strbuf.append("0");
	    	strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
	    }
	    return strbuf.toString();
	}
	
	public static String byteArrayToHex(byte[] data, int length)
	{
	    StringBuffer buf = new StringBuffer();
	    for (int i = 0; i < length; i++) {
	      int v = data[i] & 0xFF;
	      buf.append(Character.forDigit(v >> 4, 16));
	      buf.append(Character.forDigit(v & 0xF, 16));
	    }
	    return buf.toString();
	}
	
	public static byte[] hexToByteArray(String hexS)
	{
			if (hexS.length() % 2 != 0) {
			hexS = '0' + hexS;
			}
		    byte[] bArray = new byte[hexS.length() / 2];
		    for (int i = 0; i < hexS.length() / 2; i++) {
		      bArray[i] = (byte)(Character.digit(hexS.charAt(i * 2), 16) * 16 + Character.digit(hexS.charAt(i * 2 + 1), 16));
		    }
	
	    return bArray;
	}
	
	/**
	 * Simetricno sifrovanje/desifrovanje
	 * 
	 * @param opModeSymmetric - mode rada algoritma
	 * @param keyByte - vrijednost kljuca kao niz bajtova
	 * @param inputByte - vrijednost koja se treba kriptovati
	 * @param encrDecr - enkripcija/dekripcija, true/false
	 * @return encrypted/decrypted byte array
	 */
	public static byte[] symmetricEncryptDecrypt(String opModeSymmetric, 
													byte[] keyByte, 
													byte[] inputByte, 
													boolean encrDecr){
			try{
				if (Security.getProvider("BC")==null)
				Security.addProvider(new BouncyCastleProvider());
				Cipher cipher = Cipher.getInstance(opModeSymmetric,"BC");
				
				//iv initiation
				byte[] iv = null;
				String opAlg=opModeSymmetric.split("/")[0];
				String opMode = opModeSymmetric.split("/")[1];
				if(opMode.equals("CBC")){
					if(opAlg.equals("AES"))
						iv = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
					else if (opAlg.equals("DESede") || opAlg.equals("DES")) {
						iv = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
					}
					else {
						System.out.println("Nije podrzan algoritam!");
						throw new NoSuchAlgorithmException();
					}
					
					AlgorithmParameterSpec algorithmParameterSpec = new IvParameterSpec(iv);
					SecretKeySpec secretKeySpec = new SecretKeySpec(keyByte, opAlg);
					if (encrDecr)
						cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, algorithmParameterSpec);
					else 
						cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, algorithmParameterSpec);
				} else if (opMode.equals("ECB")){
					SecretKeySpec secretKeySpec = new SecretKeySpec(keyByte, opAlg);
					if (encrDecr)
						cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
					else 
						cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
				} else{
					System.out.println("Nije podrzan specificirani mod!");
					throw new NoSuchAlgorithmException();
				}
					
				return cipher.doFinal(inputByte);

			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		return null;
			
	}
	
	/**
	 * Vraca generisani kljuc na osnovu ulaznog stringa.
	 * 
	 * @param pass
	 * @return - SecretKeySpec vrijednost
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 */
	public static SecretKeySpec generateSecretKeyAES128(String pass) 
			throws UnsupportedEncodingException, NoSuchAlgorithmException{
		byte[] keyByte = pass.getBytes("UTF8");
		
		MessageDigest sha = MessageDigest.getInstance("SHA-1");
		keyByte = sha.digest(keyByte);
		keyByte = Arrays.copyOf(keyByte, 16);
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyByte, "AES");
		return secretKeySpec;
	}
	
	/**
	 * Kreiranje tajnog kljuca za AES-128.
	 * 
	 * @return vraca kljuc
	 */
	public static byte[] generateSecretKeyAES128() {
		try {
			if(Security.getProvider("BC")==null)
				Security.addProvider(new BouncyCastleProvider());
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES","BC");
			SecureRandom random = new SecureRandom();
			keyGenerator.init(128,random);
			SecretKey secretKey = keyGenerator.generateKey();
	
			byte[] keyByte = secretKey.getEncoded();
			return keyByte;
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}
	
	public static byte[] generateDESede168Key(){
		try {
			if(Security.getProvider("BC")==null)
				Security.addProvider(new BouncyCastleProvider());
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede","BC");
			SecureRandom random = new SecureRandom();
			keyGenerator.init(168, random);
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] keyByte = secretKey.getEncoded();
			return keyByte;
		
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}
	
	public static byte[] generateDESKey(){
		try {
			if(Security.getProvider("BC")==null)
				Security.addProvider(new BouncyCastleProvider());
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DES","BC");
			SecureRandom random = new SecureRandom();
			keyGenerator.init(56, random);
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] keyByte = secretKey.getEncoded();
			return keyByte;
		
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}
	
	public static byte[] generateSymmetricKey(String opAlgModePad){
		try {
			if(Security.getProvider("BC")==null)
				Security.addProvider(new BouncyCastleProvider());
			String opAlg = opAlgModePad.split("/")[0];
			KeyGenerator keyGenerator = KeyGenerator.getInstance(opAlg,"BC");
			SecureRandom random = new SecureRandom();
			
			if(opAlg.equals("AES"))
				keyGenerator.init(128,random);
			else if(opAlg.equals("DESede"))
				keyGenerator.init(168,random);
			else if(opAlg.equals("DES"))
				keyGenerator.init(56,random);
			else
				System.out.println("Nepoznat algoritam!");
			
			SecretKey secretKey = keyGenerator.generateKey();
	
			byte[] keyByte = secretKey.getEncoded();
			return keyByte;
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}
	
	public static byte[] generateSymmetricKey(String opAlgModePad, String seed){
		try {
			if(Security.getProvider("BC")==null)
				Security.addProvider(new BouncyCastleProvider());
			String opAlg = opAlgModePad.split("/")[0];
			KeyGenerator keyGenerator = KeyGenerator.getInstance(opAlg,"BC");
			SecureRandom random = new SecureRandom(seed.getBytes());
			
			if(opAlg.equals("AES"))
				keyGenerator.init(128,random);
			else if(opAlg.equals("DESede"))
				keyGenerator.init(168,random);
			else if(opAlg.equals("DES"))
				keyGenerator.init(56,random);
			else
				System.out.println("Nepoznat algoritam!");
			
			SecretKey secretKey = keyGenerator.generateKey();
	
			byte[] keyByte = secretKey.getEncoded();
			return keyByte;
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}
	
	/**
	 * Nije zavrsena
	 * 
	 * @param keySize
	 */
	public static void generateAsymmetricElGamalKeys(int keySize){
		try {
			if (Security.getProvider("BC")==null)
				Security.addProvider(new BouncyCastleProvider());
			KeyPairGenerator keyPairGenerator;
			
				keyPairGenerator = KeyPairGenerator.getInstance("ElGamal","BC");
		
			SecureRandom random = new SecureRandom();
			keyPairGenerator.initialize(512,random);
			KeyPair keyPairOgDSA = keyPairGenerator.generateKeyPair();
			KeyPair keyPairIrDSA = keyPairGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	/**
	 * Asimetricno kriptovanje/dekriptovanje
	 * 
	 * @param opModeAsymmetric - mod rada algoritma
	 * @param key - javni/privatni kljuc
	 * @param inputByte - vrijednost koja treba da se kriptuje/dekriptuje
	 * @param encrDecr - kriptovanje/dekriptovanje
	 * @return - niz kriptovanih/dekriptovanih bajtova
	 */
	public static byte[] asymmetricEncryptDecrypt(	String opModeAsymmetric, 
													Key key, 
													byte[] inputByte, 
													boolean encrDecr){
		try {
			if (Security.getProvider("BC")==null)
			Security.addProvider(new BouncyCastleProvider());
			
			Cipher cipher = Cipher.getInstance(opModeAsymmetric,"BC");
			
			if(encrDecr)
				cipher.init(Cipher.ENCRYPT_MODE, key);
			else
				cipher.init(Cipher.DECRYPT_MODE, key);
			
			return cipher.doFinal(inputByte);
			
		} catch (NoSuchAlgorithmException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
		} catch (NoSuchProviderException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
		} catch (NoSuchPaddingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
		} catch (InvalidKeyException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
		} catch (BadPaddingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
			return null;
		}
		return null;
	}
	
	//generate asymmetric keys
	public static KeyPair getAsymmetricKeys(String aliasPrivateKey, String aliasCert){
		try {		
				if(Security.getProperty("BC")==null)
					Security.addProvider(new BouncyCastleProvider());
//				KeyStore keyStore = KeyStore.getInstance("JKS");
				KeyStore keyStore;
				
					keyStore = KeyStore.getInstance("PKCS12","BC");
				
//				FileInputStream fInput = new FileInputStream("d:/store.pks");
				//FileInputStream fInput = new FileInputStream("d:/store.p12");
				//FileInputStream fInput = new FileInputStream("/home/ognjen/store.p12");
				FileInputStream fInput = new FileInputStream("store.p12");
					
				char[] storePass = {'s', 't', 'o', 'r', 'e'};
				keyStore.load(fInput, storePass);
			
//				PrivateKey privateKey = null;
				PublicKey publicKey = null;
				KeyPair keyPair = null;
				
				Key key = keyStore.getKey(aliasPrivateKey, storePass);
				if(key instanceof PrivateKey) {
					 Certificate cert = keyStore.getCertificate(aliasCert);
					 publicKey=cert.getPublicKey();
			//         privateKeyServer = (PrivateKey)key;
			         keyPair = new KeyPair(publicKey,(PrivateKey)key);
			//         System.out.println(privateKeyServer());
			//         System.out.println(publicKeyServer);
			//         privateKeyServer = keyPair.getPrivate();
				}
				
				fInput.close();
				
				return keyPair;
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Returns hash value of the specified file in <code>filepath</code>
	 * 
	 * @param filepath
	 * @return
	 */
	public static byte[] getSHA1(String filepath){
		try {
			if(Security.getProperty("BC")==null)
				Security.addProvider(new BouncyCastleProvider());
			
			File file = new File("d:/proba.txt");
			BufferedReader inFile = new BufferedReader(new FileReader(file));
			String text="",line="";
			while((line=inFile.readLine())!=null)
				text+=line+"\n";
			
			//hash 
			byte[] textByte = text.getBytes("UTF8");
			MessageDigest md = MessageDigest.getInstance("SHA-1","BC");
			md.update(textByte,0,textByte.length);
			byte[] digest = md.digest();
			inFile.close();
			return digest;
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public static byte[] getSHA1FromTextArea(String text){
		try {
			if(Security.getProperty("BC")==null)
				Security.addProvider(new BouncyCastleProvider());
			
			//hash 
			byte[] textByte = text.getBytes("UTF8");
			MessageDigest md = MessageDigest.getInstance("SHA-1","BC");
			md.update(textByte,0,textByte.length);
			byte[] digest = md.digest();
			return digest;
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Sifruje text simetricnim algoritmom, sifruje kljuc asimetricnim, desifruje kljuc asimetricnim,
	 * desifruje sifru simetricnim i desifrovanim kljucem
	 *
	 * 
	 * @param toEncrypt
	 */
	public static void rsaAndSymmetricEncryptyDecrypt(String toEncrypt){
		try{	
			//generisanje asimetricnih kljuceva
			String aliasPrivateKeyOg = "og";
			String aliasCertificateOg = "ogCert";
			String aliasPrivateKeyIr = "ir";
			String aliasCertificateIr = "irCert";
			KeyPair keyPairIr = CryptoImpl.getAsymmetricKeys(aliasPrivateKeyIr, aliasCertificateIr);
			KeyPair keyPairOg = CryptoImpl.getAsymmetricKeys(aliasPrivateKeyOg, aliasCertificateOg);		
			
			//asimetricni alg i modovi za kriptovanje
			String opModeAsymmetric = "RSA/ECB/PKCS1Padding";
	
			//simetricni alg i modovi za kriptovanje
	//		String opModeSymmetric = "AES/CBC/PKCS7Padding";
			String opModeSymmetric = "AES/ECB/PKCS7Padding";
	//		String opModeSymmetric = "DESede/ECB/PKCS7Padding";
	//		String opModeSymmetric = "DESede/CBC/PKCS7Padding";
	//		String opModeSymmetric = "DES/CBC/PKCS7Padding";
	//		String opModeSymmetric = "DES/ECB/PKCS7Padding";
			
			//generisanje simetricnih kljuceva
			byte[] keyByte = CryptoImpl.generateSecretKeyAES128();
	//		byte[] keyByte = CryptoImpl.generateDESede168Key();
	//		byte[] keyByte = CryptoImpl.generateDESKey();
	//		"Tekst za kript i dekript"
			byte[] crypt = CryptoImpl.symmetricEncryptDecrypt(opModeSymmetric, keyByte,toEncrypt.getBytes("UTF8"), true);
			byte[] envelope = CryptoImpl.asymmetricEncryptDecrypt(opModeAsymmetric, keyPairIr.getPublic(), keyByte, true);
			byte[] keyByteFromEnvelope = CryptoImpl.asymmetricEncryptDecrypt(opModeAsymmetric, keyPairIr.getPrivate(), envelope, false);	
	
			System.out.println(new String(CryptoImpl.symmetricEncryptDecrypt(opModeSymmetric, keyByteFromEnvelope, crypt, false)).trim());
	
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static byte[] rc4Cipher(byte[] input, boolean encDec){
		byte[] output = null;
		
		try {
			if (Security.getProvider("BC")==null)
				Security.addProvider(new BouncyCastleProvider());
			Cipher cipher = Cipher.getInstance("RC4", "BC");
			if(encDec)
				cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Hex.decode("732f2d33c801732b7206756cbd44f9c1"), "RC4"));
			else if(!encDec)
				cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(Hex.decode("732f2d33c801732b7206756cbd44f9c1"), "RC4"));
			else 
				System.out.println("Nesto nije u redu!!!");
			
			output = cipher.doFinal(input);
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		return output;
		
	}
	
	 
	
	public static byte[] rc4Cipher(String algorithm, char[] keyChar, byte[] input, int encDecMode, byte[] salt, int iterationCount){
		byte[] output = null;
		try {
			if(Security.getProperty("BC")==null)
				Security.addProvider(new BouncyCastleProvider());
			
			//PBEKeySpec pbeKeySpec = new PBEKeySpec(keyChar);
			PBEKeySpec pbeKeySpec = new PBEKeySpec(keyChar, salt, iterationCount);
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algorithm, "BC");
			//PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, iterationCount);
		
		Cipher cipher = Cipher.getInstance(algorithm, "BC");
		
		//cipher.init(encDecMode, keyFactory.generateSecret(pbeKeySpec), pbeParameterSpec);
		cipher.init(encDecMode, keyFactory.generateSecret(pbeKeySpec));
		
		output = cipher.doFinal(input);
		
		
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return output;
		
	}
	
	public static byte[] streamCipher(String algorithm, String keyChar, byte[] input, int encDecMode, byte[] salt, int iterationCount){
		byte[] output = new byte[5000];
		
		if(Security.getProperty("BC")==null)
			Security.addProvider(new BouncyCastleProvider());
		
		
		if(algorithm.equals("rc4")){
			
			SecretKeySpec secretKeySpec = new SecretKeySpec(keyChar.getBytes(), "RC4");
			RC4Engine rc4Engine = new RC4Engine();
			
			CipherParameters param = new KeyParameter(secretKeySpec.getEncoded());
			if(encDecMode == Cipher.ENCRYPT_MODE){
				rc4Engine.init(true, param);
			}
			else{
				rc4Engine.init(false, param);
			}
			
			byte[] temp = new byte[1024];
			rc4Engine.processBytes(temp, 0, temp.length, temp, 0);
			
			rc4Engine.processBytes(input, 0, input.length, output, 0);
		}
		else if(algorithm.equals("salsa20")){
			SecretKeySpec secretKeySpec = new SecretKeySpec(keyChar.getBytes(), "SALSA20");
			 
			Salsa20Engine salsa20Engine = new Salsa20Engine();
			
			CipherParameters param = new KeyParameter(secretKeySpec.getEncoded());
			
			KeyParameter keyParameter = new KeyParameter((keyChar+"12345678901").getBytes());
			ParametersWithIV params = new ParametersWithIV(keyParameter, "12345678".getBytes());
			
			if(encDecMode == Cipher.ENCRYPT_MODE){
				salsa20Engine.init(true, params);
			}
			else{
				salsa20Engine.init(false, params);
			}
			
			byte[] temp = new byte[1024];
			salsa20Engine.processBytes(temp, 0, temp.length, temp, 0);
			
			salsa20Engine.processBytes(input, 0, input.length, output, 0);
		}
		else{
			//PBEWithSHAAnd128BitRC4"
				output = rc4Cipher(algorithm, keyChar.toCharArray(), input, encDecMode, salt, iterationCount);
			//return output;

		}

		return output;
	}
	
	
	/**
	 * Imports Key.
	 * 
	 * @param keyPath
	 * @return
	 * @throws IOException
	 */
	public static KeyPair getKeyPair(String keyPath) throws IOException{
		File filePrivateKey = new File(keyPath);
		KeyPair keyPair = null;
		if(filePrivateKey.exists()){
			BufferedReader bufferedReader = new BufferedReader(new FileReader(filePrivateKey));
			PEMParser pemParser = new PEMParser(bufferedReader);
			PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
			keyPair = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
			pemParser.close();
		}
		else
			System.out.println("There is no Key on path: " + keyPath );
		
		return keyPair;
	}
	
	/**
	 * Imports Key.
	 * 
	 * @param keyPath
	 * @return
	 * @throws IOException
	 */
	public static KeyPair getKeyPair(File filePrivateKey) throws IOException{
		KeyPair keyPair = null;
		if(filePrivateKey.exists()){
			BufferedReader bufferedReader = new BufferedReader(new FileReader(filePrivateKey));
			PEMParser pemParser = new PEMParser(bufferedReader);
			PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
			keyPair = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
			pemParser.close();
		}
		else
			System.out.println("There is no Key on path");
		
		return keyPair;
	}
	
	/**
	 * Imports Key.
	 * 
	 * @param keyPath
	 * @return
	 * @throws IOException
	 */
	public static PublicKey getPublicKey(String keyPath) throws IOException{
		File filePrivateKey = new File(keyPath);
		KeyPair keyPair = null;
		PublicKey pubKey = null;
		if(filePrivateKey.exists()){
			BufferedReader bufferedReader = new BufferedReader(new FileReader(filePrivateKey));
			PEMParser pemParser = new PEMParser(bufferedReader);
			//PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
			SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(pemParser.readObject());
			//keyPair = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
			pubKey = new JcaPEMKeyConverter().getPublicKey(pubInfo);
			pemParser.close();
		}
		else
			System.out.println("There is no Key on path: " + keyPath );
		
		return pubKey;
	}
	
	/**
	 * Ne radi
	 * Imports Key with password protection.
	 * 
	 * @param keyPath
	 * @return
	 * @throws IOException
	 */
	public static KeyPair getKeyPair(String keyPath, String password) throws IOException{
		File filePrivateKey = new File(keyPath);
		System.out.println("pwd: " + System.getProperty("user.dir") + keyPath);
		KeyPair keyPair = null;
		if(filePrivateKey.exists()){
			BufferedReader bufferedReader = new BufferedReader(new FileReader(filePrivateKey));
			PEMParser pemParser = new PEMParser(bufferedReader);
			//PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
			Object keyPairObj = pemParser.readObject();
			
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
			PEMDecryptorProvider decryptProvider = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
			
			
			PEMKeyPair pemKeyPair = (PEMKeyPair)((PEMEncryptedKeyPair) keyPairObj).decryptKeyPair(decryptProvider);
			keyPair = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
			pemParser.close();
		}
		else
			System.out.println("There is no Key on path: " + keyPath );
		
		return keyPair;
	}
	
	/**
	 * Imports private key with password protection.
	 * 
	 * @param keyPath
	 * @return
	 * @throws IOException
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws InvalidKeyException 
	 */
	public static PrivateKey getPrivateKey(String keyPath, String password) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException{
		File filePrivateKey = new File(keyPath);
		FileInputStream fis = new FileInputStream(keyPath);
		DataInputStream dis = new DataInputStream(fis);
		byte[] keyBytes = new byte[(int)filePrivateKey.length()];
		dis.readFully(keyBytes);
		dis.close();
		
		EncryptedPrivateKeyInfo encryptedPKInfo = new EncryptedPrivateKeyInfo(keyBytes);
		Cipher cipherPKey = Cipher.getInstance(encryptedPKInfo.getAlgName());
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory secKeyFac = SecretKeyFactory.getInstance(encryptedPKInfo.getAlgName());
		Key pbeKey = secKeyFac.generateSecret(pbeKeySpec);
		AlgorithmParameters algParams = encryptedPKInfo.getAlgParameters();
		cipherPKey.init(Cipher.DECRYPT_MODE, pbeKey, algParams);
		KeySpec pkcs8KeySpec = encryptedPKInfo.getKeySpec(cipherPKey);
		KeyFactory keyFac = KeyFactory.getInstance("RSA");
		
		
		System.out.println("pwd: " + System.getProperty("user.dir") + keyPath);
//		KeyPair keyPair = null;
//		if(filePrivateKey.exists()){
//			BufferedReader bufferedReader = new BufferedReader(new FileReader(filePrivateKey));
//			PEMParser pemParser = new PEMParser(bufferedReader);
//			PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
//			keyPair = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
//			pemParser.close();
//		}
//		else
//			System.out.println("There is no Key on path: " + keyPath );
		
		PrivateKey privKey = keyFac.generatePrivate(pkcs8KeySpec);
		return privKey;
//		return keyPair;
	}
	
	/**
	 * Imports public key with password protection.
	 * 
	 * @param keyPath
	 * @return
	 * @throws IOException
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws InvalidKeyException 
	 */
	public static PublicKey getPublicKey(String keyPath, String password) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException{
		File filePrivateKey = new File(keyPath);
		FileInputStream fis = new FileInputStream(keyPath);
		DataInputStream dis = new DataInputStream(fis);
		byte[] keyBytes = new byte[(int)filePrivateKey.length()];
		dis.readFully(keyBytes);
		dis.close();
		
		EncryptedPrivateKeyInfo encryptedPKInfo = new EncryptedPrivateKeyInfo(keyBytes);
		Cipher cipherPKey = Cipher.getInstance(encryptedPKInfo.getAlgName());
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory secKeyFac = SecretKeyFactory.getInstance(encryptedPKInfo.getAlgName());
		Key pbeKey = secKeyFac.generateSecret(pbeKeySpec);
		AlgorithmParameters algParams = encryptedPKInfo.getAlgParameters();
		cipherPKey.init(Cipher.DECRYPT_MODE, pbeKey, algParams);
		//needs to be DER
		KeySpec pkcs8KeySpec = encryptedPKInfo.getKeySpec(cipherPKey);
		KeyFactory keyFac = KeyFactory.getInstance("RSA");
		
		
		System.out.println("pwd: " + System.getProperty("user.dir") + keyPath);
//		KeyPair keyPair = null;
//		if(filePrivateKey.exists()){
//			BufferedReader bufferedReader = new BufferedReader(new FileReader(filePrivateKey));
//			PEMParser pemParser = new PEMParser(bufferedReader);
//			PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
//			keyPair = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
//			pemParser.close();
//		}
//		else
//			System.out.println("There is no Key on path: " + keyPath );
		
		PublicKey pubKey = keyFac.generatePublic(pkcs8KeySpec);
		return pubKey;
//		return keyPair;
	}
	
	public static byte[] hash(String digestAlgorithm, byte[] message){
		if(Security.getProperty("BC")==null)
			Security.addProvider(new BouncyCastleProvider());
		
		Digest digest = null; 
		
		if(digestAlgorithm.equals(new SHA256Digest().getAlgorithmName()))
			digest = new SHA256Digest();
		else if (digestAlgorithm.equals(new SHA512Digest().getAlgorithmName())) 
			digest = new SHA512Digest();
		else
			return null;
		
		byte[] digestBytes = new byte[digest.getDigestSize()];
		digest.update(message, 0, message.length);
		digest.doFinal(digestBytes, 0);

		return digestBytes;
		
	}
	
}
