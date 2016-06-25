package secureLib;

import java.io.*;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Hashtable;
import java.util.Vector;


import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.RSAUtil;
import org.bouncycastle.jcajce.provider.symmetric.AES.KeyGen;
import org.bouncycastle.jcajce.provider.symmetric.AES.KeyGen128;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.omg.Dynamic.Parameter;

public class CertificateKlasa {

	static X509V1CertificateGenerator  v1CertGen = new X509V1CertificateGenerator();
	static X509V3CertificateGenerator  v3CertGen = new X509V3CertificateGenerator();
	
	
	public CertificateKlasa(){
		main(null);
	}
	
	/**
	 * @param args
	 * @throws KeyStoreException 
	 * @throws NoSuchAlgorithmException 
	 */
	public static void main(String[] args) {
		try {
					
					if (Security.getProvider("BC")==null)
						Security.addProvider(new BouncyCastleProvider());
					//generate asymmetric keys
					KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
					
					SecureRandom random = new SecureRandom();
					keyPairGenerator.initialize(2048,random);
//					keyPairGenerator.initialize(8192,random);
					KeyPair keyPairOg = keyPairGenerator.generateKeyPair();
					KeyPair keyPairIr = keyPairGenerator.generateKeyPair();
					KeyPair keyPairIntermediate = keyPairGenerator.generateKeyPair();
					Key privateKeyIr = keyPairIr.getPrivate();
					Key publicKeyIr = keyPairIr.getPublic();
					System.out.println("ir private: "+privateKeyIr);
					System.out.println("ir public: "+publicKeyIr);
					
					//certificate
//					keyPairGenerator.initialize(4096,random);
					KeyPair keyPairCA = keyPairGenerator.generateKeyPair();
//					keyPairGenerator.initialize(2048,random);
					
					Certificate[] chainCertificate = new Certificate[4];
					chainCertificate[0] = createMasterCert(keyPairCA.getPublic(), keyPairCA.getPrivate());
					chainCertificate[1] = createIntermediateCert(keyPairIntermediate.getPublic(), keyPairCA.getPrivate(), (X509Certificate)chainCertificate[0]);
					chainCertificate[2] = createCert(keyPairIr.getPublic(), keyPairCA.getPrivate(), keyPairCA.getPublic());
					chainCertificate[3] = createCert(keyPairOg.getPublic(), keyPairCA.getPrivate(), keyPairCA.getPublic());
					
					//keyStore
					char[] storePasswd = {'s','t','o','r','e'};
					KeyStore keyStore = KeyStore.getInstance("PKCS12","BC");
//					KeyStore keyStore = KeyStore.getInstance("JKS");
					keyStore.load(null,null);
					keyStore.setKeyEntry("og", keyPairOg.getPrivate(), storePasswd, chainCertificate);
					keyStore.setKeyEntry("ir", keyPairIr.getPrivate(), storePasswd, chainCertificate);
					keyStore.setCertificateEntry("irCert", (X509Certificate)chainCertificate[2]);
					keyStore.setCertificateEntry("ogCert", (X509Certificate)chainCertificate[3]);
					
					 
					//store keyStore into file
					FileOutputStream fOut = new FileOutputStream("store.p12");
					//FileOutputStream fOut = new FileOutputStream("/home/ognjen/store.p12");
					//FileOutputStream fOut = new FileOutputStream("d:/store.p12");
//					FileOutputStream fOut = new FileOutputStream("d:/store.pks");
					keyStore.store(fOut, storePasswd);
					
//					FileInputStream fInput = new FileInputStream("d:/store.p12");
//					KeyStore	kStore = KeyStore.getInstance("PKCS12","BC");
					
					System.out.println("store.p12 kreiran u "+new Date());
					//System.out.println("/home/ognjen/store.p12 kreiran u "+new Date());
					//System.out.println("d:/store.p12 kreiran u "+new Date());
//					System.out.println("d:/store.pks kreiran u "+new Date());
					
					//close connections
					fOut.close();
		
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static Certificate createMasterCert(
            PublicKey       pubKey,
            PrivateKey      privKey)
            throws Exception
        {
            //
            // signers name 
            //
            String  issuer = "C=AU, O=The Legion of the Bouncy Castle, OU=Bouncy Primary Certificate";
    
            //
            // subjects name - the same as we are self signed.
            //
            String  subject = "C=AU, O=The Legion of the Bouncy Castle, OU=Bouncy Primary Certificate";
    
            //
            // create the certificate - version 1
            //
    
            v1CertGen.setSerialNumber(BigInteger.valueOf(1));
            v1CertGen.setIssuerDN(new X509Principal(issuer));
            v1CertGen.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30));
            v1CertGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)));
            v1CertGen.setSubjectDN(new X509Principal(subject));
            v1CertGen.setPublicKey(pubKey);
            v1CertGen.setSignatureAlgorithm("SHA1WithRSAEncryption");
    
            X509Certificate cert = v1CertGen.generateX509Certificate(privKey);
    
            cert.checkValidity(new Date());
    
            cert.verify(pubKey);
    
            PKCS12BagAttributeCarrier   bagAttr = (PKCS12BagAttributeCarrier)cert;
    
            //
            // this is actually optional - but if you want to have control
            // over setting the friendly name this is the way to do it...
            //
            bagAttr.setBagAttribute(
                PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                new DERBMPString("Bouncy Primary Certificate"));
    
            return cert;
        }
    
        /**
         * we generate an intermediate certificate signed by our CA
         */
        public static Certificate createIntermediateCert(
            PublicKey       pubKey,
            PrivateKey      caPrivKey,
           X509Certificate caCert)
           throws Exception
       {
           //
           // subject name table.
           //
           Hashtable                   attrs = new Hashtable();
           Vector                      order = new Vector();
   
           attrs.put(X509Principal.C, "AU");
           attrs.put(X509Principal.O, "The Legion of the Bouncy Castle");
           attrs.put(X509Principal.OU, "Bouncy Intermediate Certificate");
           attrs.put(X509Principal.EmailAddress, "feedback-crypto@bouncycastle.org");
   
           order.addElement(X509Principal.C);
           order.addElement(X509Principal.O);
           order.addElement(X509Principal.OU);
           order.addElement(X509Principal.EmailAddress);
   
           //
           // create the certificate - version 3
           //
           v3CertGen.reset();
   
           v3CertGen.setSerialNumber(BigInteger.valueOf(2));
           v3CertGen.setIssuerDN(PrincipalUtil.getSubjectX509Principal(caCert));
           v3CertGen.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30));
           v3CertGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)));
           v3CertGen.setSubjectDN(new X509Principal(order, attrs));
           v3CertGen.setPublicKey(pubKey);
           v3CertGen.setSignatureAlgorithm("SHA1WithRSAEncryption");
   
           //
           // extensions
           //
           v3CertGen.addExtension(
               X509Extensions.SubjectKeyIdentifier,
               false,
               new SubjectKeyIdentifierStructure(pubKey));
   
           v3CertGen.addExtension(
               X509Extensions.AuthorityKeyIdentifier,
               false,
               new AuthorityKeyIdentifierStructure(caCert));
   
           v3CertGen.addExtension(
               X509Extensions.BasicConstraints,
               true,
               new BasicConstraints(0));
   
           X509Certificate cert = v3CertGen.generateX509Certificate(caPrivKey);
   
           cert.checkValidity(new Date());
   
           cert.verify(caCert.getPublicKey());
   
           PKCS12BagAttributeCarrier   bagAttr = (PKCS12BagAttributeCarrier)cert;
   
           //
           // this is actually optional - but if you want to have control
           // over setting the friendly name this is the way to do it...
           //
           bagAttr.setBagAttribute(
               PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
               new DERBMPString("Bouncy Intermediate Certificate"));
   
           return cert;
       }
   
       /**
        * we generate a certificate signed by our CA's intermediate certficate
        */
       public static Certificate createCert(
           PublicKey       pubKey,
           PrivateKey      caPrivKey,
           PublicKey       caPubKey)
           throws Exception
       {
           //
           // signers name table.
           //
           Hashtable                   sAttrs = new Hashtable();
           Vector                      sOrder = new Vector();
   
           sAttrs.put(X509Principal.C, "AU");
           sAttrs.put(X509Principal.O, "The Legion of the Bouncy Castle");
           sAttrs.put(X509Principal.OU, "Bouncy Intermediate Certificate");
           sAttrs.put(X509Principal.EmailAddress, "feedback-crypto@bouncycastle.org");
   
           sOrder.addElement(X509Principal.C);
           sOrder.addElement(X509Principal.O);
           sOrder.addElement(X509Principal.OU);
           sOrder.addElement(X509Principal.EmailAddress);
   
           //
           // subjects name table.
           //
           Hashtable                   attrs = new Hashtable();
           Vector                      order = new Vector();
   
           attrs.put(X509Principal.C, "AU");
           attrs.put(X509Principal.O, "The Legion of the Bouncy Castle");
           attrs.put(X509Principal.L, "Melbourne");
           attrs.put(X509Principal.CN, "Eric H. Echidna");
           attrs.put(X509Principal.EmailAddress, "feedback-crypto@bouncycastle.org");
   
           order.addElement(X509Principal.C);
           order.addElement(X509Principal.O);
           order.addElement(X509Principal.L);
           order.addElement(X509Principal.CN);
           order.addElement(X509Principal.EmailAddress);
   
           //
           // create the certificate - version 3
           //
           v3CertGen.reset();
   
           v3CertGen.setSerialNumber(BigInteger.valueOf(3));
           v3CertGen.setIssuerDN(new X509Principal(sOrder, sAttrs));
           v3CertGen.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30));
           v3CertGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30)));
           v3CertGen.setSubjectDN(new X509Principal(order, attrs));
           v3CertGen.setPublicKey(pubKey);
           v3CertGen.setSignatureAlgorithm("SHA1WithRSAEncryption");
   
           //
           // add the extensions
           //
           v3CertGen.addExtension(
               X509Extensions.SubjectKeyIdentifier,
               false,
               new SubjectKeyIdentifierStructure(pubKey));
   
           v3CertGen.addExtension(
               X509Extensions.AuthorityKeyIdentifier,
               false,
               new AuthorityKeyIdentifierStructure(caPubKey));
   
           X509Certificate cert = v3CertGen.generateX509Certificate(caPrivKey);
   
           cert.checkValidity(new Date());
   
           cert.verify(caPubKey);
   
           PKCS12BagAttributeCarrier   bagAttr = (PKCS12BagAttributeCarrier)cert;
   
           //
           // this is also optional - in the sense that if you leave this
           // out the keystore will add it automatically, note though that
           // for the browser to recognise the associated private key this
           // you should at least use the pkcs_9_localKeyId OID and set it
           // to the same as you do for the private key's localKeyId.
           //
           bagAttr.setBagAttribute(
               PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
               new DERBMPString("Eric's Key"));
           bagAttr.setBagAttribute(
               PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
               new SubjectKeyIdentifierStructure(pubKey));
   
           return cert;
       }
       
}
