package secureLib;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;


public class CryptoDevelop {


	
	/**
	 * @param args
	 */
	public static void main(String[] args){
		try {
			if (Security.getProvider("BC")==null)
				Security.addProvider(new BouncyCastleProvider());
			
			String toEncrypt = "Tekst za sifrovanje.";
			byte[] toEncryptByteArray = toEncrypt.getBytes("UTF8");
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ElGamal","BC");
			SecureRandom random = new SecureRandom();
			keyPairGenerator.initialize(512,random);
//			KeyPair keyPairOgElGamal = keyPairGenerator.generateKeyPair();
			KeyPair keyPairIrElGamal = keyPairGenerator.generateKeyPair();
			Key privateKeyIrElGamal = keyPairIrElGamal.getPrivate();
			Key publicKeyIrElGamal = keyPairIrElGamal.getPublic();
			File filePrivateIr = new File("irPrivate.key");
			PrintStream outputPrintStream = new PrintStream(new FileOutputStream(filePrivateIr));
//			FileInputStream inputFileInputStream = new FileInputStream("d:/irPublic.key");
			
			
			outputPrintStream.print(publicKeyIrElGamal.getEncoded());
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			outputPrintStream.close();
			
			FileInputStream inputFileInputStream = new FileInputStream(filePrivateIr);
			int theByte = 0;
			while ((theByte = inputFileInputStream.read())!=-1){
				baos.write(theByte);
				System.out.println(theByte);
				System.out.println(baos.size());
				System.out.println(baos.toString());
			}
			
			System.out.println(theByte);
			System.out.println(baos.size());
			inputFileInputStream.close();
			
			byte[] keyIrPublic = baos.toByteArray();
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyIrPublic);
		    KeyFactory keyFactory = KeyFactory.getInstance("ElGamal","BC");
			Key irPublicKey = keyFactory.generatePrivate(keySpec);
			
			Cipher cipher = Cipher.getInstance("ElGamal/ECB/PKCS1Padding","BC");
			cipher.init(Cipher.ENCRYPT_MODE, irPublicKey);
			byte[] cryptoByteArray = cipher.doFinal(toEncryptByteArray);
			cipher.init(Cipher.DECRYPT_MODE, privateKeyIrElGamal);
			byte[] decrypt = cipher.doFinal(cryptoByteArray);
			System.out.println(new String(decrypt));
			
//			bufferedWriter.close();

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
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

}
