package implementation;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import code.GuiException;
import gui.Constants;
import gui.GuiInterfaceV1;
import x509.v3.*;

public class MyCode extends CodeV3
{
	private KeyStore keystore;
	private KeyPairGenerator generator;
	private JcaPKCS10CertificationRequest myCSR;
	private static final String ksPass = "sifra";

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException 
	{
		super(algorithm_conf, extensions_conf, extensions_rules);
		try 
		{ 
			keystore = KeyStore.getInstance("PKCS12", new BouncyCastleProvider());
			keystore.load(null, ksPass.toCharArray());
			generator = KeyPairGenerator.getInstance("DSA");
			myCSR = null;
		}
		catch (Exception e) 
		{ 
			e.printStackTrace(); 
		}
	}

	@Override
	public boolean canSign(String keypair_name) 
	{
		try 
		{
			X509Certificate cert;
			cert = (X509Certificate)keystore.getCertificate(keypair_name);
			return cert.getBasicConstraints() != -1;
		} 
		catch (KeyStoreException e) 
		{
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public boolean exportCSR(String file, String keypair_name, String algorithm)
	{
		try 
		{
			X509Certificate cert = (X509Certificate)keystore.getCertificate(keypair_name);
			PublicKey publicKey = cert.getPublicKey();
			PrivateKey privateKey = (PrivateKey)keystore.getKey(keypair_name, null);
			
			X500Name subject = new X500Name(cert.getSubjectX500Principal().getName());
			PKCS10CertificationRequestBuilder pkcs10builder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);
			JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(algorithm);
			ContentSigner contentSigner = csBuilder.build(privateKey);
			PKCS10CertificationRequest csr = pkcs10builder.build(contentSigner);
			
			FileOutputStream out = new FileOutputStream(file);
			byte[] output = csr.getEncoded();
			out.write(output);
			
			out.close();
			return true;
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public boolean exportCertificate(String file, String keypair_name, int encoding, int format) 
	{
		try
		{
			Certificate[] chain = keystore.getCertificateChain(keypair_name);
			X509Certificate cert = (X509Certificate)keystore.getCertificate(keypair_name);
			
			int n;
			if (format == 0)
				n = 1;
			else
				n = chain.length;
			
			if (encoding == Constants.DER) // DER
			{
				FileOutputStream out = new FileOutputStream(file);
				out.write(cert.getEncoded());
				out.close();
			}
			else if (encoding == Constants.PEM) // PEM
			{
				FileWriter fw = new FileWriter(file);
				JcaPEMWriter pemWriter = new JcaPEMWriter(fw);
				
				if (format == Constants.HEAD)
					pemWriter.writeObject(cert);
				else if (format == Constants.CHAIN)
				{
					for(int i = 0; i < chain.length; i++)
						pemWriter.writeObject(chain[i]);
				}
				pemWriter.close();
				fw.close();
			}
		}
		catch (Exception e)
		{
			e.printStackTrace();
			return false;
		}
		return true;
	}
	

	@Override
	public boolean exportKeypair(String keypair_name, String file, String password) 
	{
		try
		{
			FileOutputStream out = new FileOutputStream(file);
			
			KeyStore tempKS = KeyStore.getInstance("PKCS12");
			tempKS.load(null, null);
			
			Certificate[] chain = keystore.getCertificateChain(keypair_name);
			Key key = keystore.getKey(keypair_name, ksPass.toCharArray());
			
			tempKS.setKeyEntry(keypair_name, key, password.toCharArray(), chain);
			tempKS.store(out, password.toCharArray());
			
			out.close();
		}
		catch (Exception e)
		{
			e.printStackTrace();
			return false;
		}
		return true;
	}

	@Override
	public String getCertPublicKeyAlgorithm(String keypair_name)
	{
		try 
		{
			X509Certificate cert;
			cert = (X509Certificate)keystore.getCertificate(keypair_name);
			return cert.getPublicKey().getAlgorithm();
		}
		catch (KeyStoreException e) 
		{
			e.printStackTrace();
		}
		return null;
	}

	@Override 
	public String getCertPublicKeyParameter(String keypair_name)
	{
		try 
		{
			if (keystore.getCertificate(keypair_name).getPublicKey().getAlgorithm().equals("RSA")) 
			{
				RSAPublicKey publicKey = (RSAPublicKey)keystore.getCertificate(keypair_name).getPublicKey();
				return publicKey.getModulus().bitLength() + "";
			}
		} 
		catch (KeyStoreException e) 
		{
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public String getSubjectInfo(String keypair_name) 
	{
		try 
		{
			X509Certificate cert = (X509Certificate)keystore.getCertificate(keypair_name);
			return cert.getSubjectX500Principal().getName("RFC1779");
		} 
		catch (KeyStoreException e) 
		{
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public boolean importCAReply(String file, String keypair_name) 
	{
		try
		{
			Path path = Paths.get(file);
			byte[] data = Files.readAllBytes(path);
			CMSSignedData signedData = new CMSSignedData(data);
			
			Store<X509CertificateHolder> store = signedData.getCertificates();
			Collection<X509CertificateHolder> collection = store.getMatches(null);
			Certificate[] chain = new Certificate[collection.size()];
			
			int i = 0;
			for(X509CertificateHolder holder : collection)
			{
				X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
				chain[i++] = cert;
			}
			
			PublicKey publicKey = chain[0].getPublicKey();
			PrivateKey privateKey = (PrivateKey)keystore.getKey(keypair_name, ksPass.toCharArray());
			
			X509Certificate cert = (X509Certificate)chain[0];
			
			if (!publicKey.equals(cert.getPublicKey()))
			{
				GuiInterfaceV1.reportError("CA reply ne odgovara selektovanom kljucu!");
				return false;
			}
			
			Certificate[] newChain = new Certificate[chain.length - 1];
			for(i = 0; i < newChain.length; i++)
				newChain[i] = chain[i + 1];
			keystore.deleteEntry(keypair_name);
			keystore.setKeyEntry(keypair_name, privateKey, ksPass.toCharArray(), chain);
			
			loadKeypair(keypair_name);
			return true;
		}
		catch (Exception e)
		{
			e.printStackTrace();
			return false;
		}
		
	}

	@Override
	public String importCSR(String file)
	{
		try
		{
			FileInputStream in = new FileInputStream(file);
			byte[] input = new byte[in.available()];
			in.read(input);
			JcaPKCS10CertificationRequest csr = new JcaPKCS10CertificationRequest(input);
			myCSR = csr;
			in.close();
			return csr.getSubject().toString();
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public boolean importCertificate(String file, String keypair_name) 
	{
		try
		{
			if (keystore.getCertificate(keypair_name) != null)
			{
				GuiInterfaceV1.reportError("Greska! Sertifikat sa tim imenom vec postoji!");
				return false;
			}
			
			FileInputStream in = new FileInputStream(file);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate cert = (X509Certificate)cf.generateCertificate(in);
			keystore.setCertificateEntry(keypair_name, cert);
			in.close();
		}
		catch (Exception e)
		{
			e.printStackTrace();
			return false;
		}
		return true;
	}

	@Override
	public boolean importKeypair(String keypair_name, String file, String password) 
	{
		try
		{
			if (keystore.getCertificate(keypair_name) != null)
			{
				GuiInterfaceV1.reportError("Greska! Sertifikat sa tim imenom vec postoji!");
				return false;
			}
			
			KeyStore tempKS = KeyStore.getInstance("PKCS12");
			InputStream in = new FileInputStream(file);
			tempKS.load(in, password.toCharArray());
			
			String alias = tempKS.aliases().nextElement();
			Certificate[] chain = tempKS.getCertificateChain(alias);
			Key key = tempKS.getKey(alias, password.toCharArray());
			
			keystore.setKeyEntry(keypair_name, (PrivateKey)key, ksPass.toCharArray(), chain);
			
			in.close();
			return true;
		}
		catch (Exception e)
		{
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public int loadKeypair(String keypair_name) 
	{
		X509Certificate subject;
		try
		{
			subject = (X509Certificate)keystore.getCertificate(keypair_name);
			Certificate[] chain = keystore.getCertificateChain(keypair_name);
			if (chain != null)
			{
				Certificate[] newChain = new Certificate[chain.length];
				for(int i = 0; i < newChain.length; i++)
					newChain[i] = chain[i];
			}
			
			super.access.setSubject(subject.getSubjectX500Principal().getName());
			super.access.setSubjectSignatureAlgorithm(subject.getPublicKey().getAlgorithm());
			
			super.access.setIssuer(subject.getIssuerX500Principal().getName());
			super.access.setIssuerSignatureAlgorithm(subject.getSigAlgName());
			
			super.access.setVersion(subject.getVersion() - 1);
			super.access.setSerialNumber(subject.getSerialNumber().toString());
			super.access.setNotBefore(subject.getNotBefore());
			super.access.setNotAfter(subject.getNotAfter());
			
			super.access.setPublicKeyAlgorithm(subject.getPublicKey().getAlgorithm());
			
	//		super.access.setPublicKeyAlgorithm(subject.getPublicKey().getAlgorithm());
	//		super.access.setPublicKeyParameter(getCertPublicKeyParameter(keypair_name));
	//		super.access.setPublicKeyDigestAlgorithm(subject.getPublicKey().getAlgorithm());
			
			
			if (subject.getCriticalExtensionOIDs() != null)
			{
				access.setCritical(3, subject.getCriticalExtensionOIDs().contains(Extension.certificatePolicies.toString()));
				access.setCritical(5, subject.getCriticalExtensionOIDs().contains(Extension.subjectAlternativeName.toString()));
				access.setCritical(8, subject.getCriticalExtensionOIDs().contains(Extension.basicConstraints.toString()));
			}
			
			/* 		Certificate policies	 */
			byte[] policies = subject.getExtensionValue(Extension.certificatePolicies.toString());
			if (policies != null)
			{
				CertificatePolicies certPolicies = CertificatePolicies.getInstance(X509ExtensionUtil.fromExtensionValue(policies));
				PolicyInformation[] policyInfo = certPolicies.getPolicyInformation();
				for (PolicyInformation pInfo : policyInfo)
				{
					ASN1Sequence policyQualifier = (ASN1Sequence)pInfo.getPolicyQualifiers().getObjectAt(0);
					if (policyQualifier.getObjectAt(0).equals(PolicyQualifierId.id_qt_cps))
					{
						String cpsUri = policyQualifier.getObjectAt(1).toString();
						super.access.setAnyPolicy(true);
						super.access.setCpsUri(cpsUri);
					}
				}
			}
			
			/*		Subject alternative names		*/
			Collection<List<?>> collection = subject.getSubjectAlternativeNames();
			if (collection != null)
			{
				String altNames = "";
				for (List<?> list : collection)
					altNames += list.get(1) + ", ";
				altNames = altNames.substring(0, altNames.length() - 2);
				access.setAlternativeName(Constants.SAN, altNames);
			}
			
			/*			Basic constraints		*/
			int pathLen = subject.getBasicConstraints();
			if (pathLen != -1) // is CA
			{
				access.setCA(true);
				access.setPathLen(pathLen + "");
			}
			
			if (subject.getBasicConstraints() != -1)
				return 2;
			else if ((subject.getSubjectX500Principal().getName()).equals(subject.getIssuerX500Principal().getName()))
				return 0;
			else
				return 1;
		}
		catch (Exception e)
		{
			e.printStackTrace();
			return -1;
		}
	}

	@Override
	public Enumeration<String> loadLocalKeystore() 
	{
		if (keystore != null)
		{
			try 
			{
				return keystore.aliases();
			} 
			catch (Exception e) 
			{
				e.printStackTrace();
			}
		}
		return null;
	}

	@Override
	public boolean removeKeypair(String keypair_name)
	{
		try 
		{
			keystore.deleteEntry(keypair_name);
			return true;
		} 
		catch (KeyStoreException e) 
		{
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public void resetLocalKeystore() 
	{
		if (keystore == null)
			return;
		try
		{
			Enumeration<String> aliases = keystore.aliases();
			
			while (aliases.hasMoreElements())
			{
				String temp = aliases.nextElement();
				keystore.deleteEntry(temp);
			}
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
	}

	@Override
	public boolean saveKeypair(String keypair_name) 
	{
		try
		{
			if (keystore.getCertificate(keypair_name) != null)
			{
				GuiInterfaceV1.reportError("Greska! Sertifikat sa tim imenom vec postoji!");
				return false;
			}
			
			if (access.getVersion() != 2)
			{
				GuiInterfaceV1.reportError("Greska! Dozvoljeno je praviti samo sertifikate verzije 3!");
				return false;
			}
			
			generator.initialize(Integer.parseInt(super.access.getPublicKeyParameter()));
			KeyPair keyPair = generator.generateKeyPair();
			
			X500Name subject = new X500Name(access.getSubject());
			X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
					subject,
					new BigInteger (access.getSerialNumber()), 
					access.getNotBefore(),
					access.getNotAfter(),
					subject,
					keyPair.getPublic()
					);
			
			/*		   Certificate policies   		*/ 
			PolicyQualifierInfo policyQualifierInfo = new PolicyQualifierInfo(access.getCpsUri().toString());
			PolicyInformation policyInformation = new PolicyInformation(PolicyQualifierId.id_qt_cps, new DERSequence(policyQualifierInfo));
			certBuilder.addExtension(Extension.certificatePolicies, access.isCritical(13), new CertificatePolicies(policyInformation));
			
			/*		Subject alternative names		*/
			String[] altNames = access.getAlternativeName(Constants.SAN);
			GeneralName[] genNames = new GeneralName[altNames.length];
			for (int i = 0; i < altNames.length; i++)
				genNames[i] = new GeneralName(GeneralName.rfc822Name, new DERIA5String(altNames[i]));
			certBuilder.addExtension(Extension.subjectAlternativeName, access.isCritical(5), new GeneralNames(genNames));
			
			BasicConstraints bc;
			if (access.isCA())
				bc = new BasicConstraints(Integer.parseInt(access.getPathLen()));
			else
				bc = new BasicConstraints(false);
			certBuilder.addExtension(Extension.basicConstraints, access.isCritical(8), bc);
		
			JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(access.getPublicKeyDigestAlgorithm());
			ContentSigner contentSigner = csBuilder.build(keyPair.getPrivate());
			X509Certificate	cert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));
			
			keystore.setKeyEntry(keypair_name, keyPair.getPrivate(), ksPass.toCharArray(), new Certificate[] {cert});
			return true;
		}
		catch (Exception e)
		{
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public boolean signCSR(String file, String keypair_name, String algorithm) 
	{
		try 
		{
			if (access.getVersion() != 2)
			{
				GuiInterfaceV1.reportError("Greska! Dozvoljeno je praviti samo sertifikate verzije 3!");
				return false;
			}
			
			X509Certificate issuer = (X509Certificate)keystore.getCertificate(keypair_name);
			X500Name subject = new X500Name(access.getSubject());
			
			PublicKey publicKey = myCSR.getPublicKey();
			
			X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
					issuer,
					new BigInteger (access.getSerialNumber()), 
					access.getNotBefore(),
					access.getNotAfter(),
					subject,
					publicKey
					);
			
			/*		   Certificate policies   		*/ 
			PolicyQualifierInfo policyQualifierInfo = new PolicyQualifierInfo(access.getCpsUri().toString());
			PolicyInformation policyInformation = new PolicyInformation(PolicyQualifierId.id_qt_cps, new DERSequence(policyQualifierInfo));
			certBuilder.addExtension(Extension.certificatePolicies, access.isCritical(13), new CertificatePolicies(policyInformation));
			
			/*		Subject alternative names		*/
			String[] altNames = access.getAlternativeName(Constants.SAN);
			GeneralName[] genNames = new GeneralName[altNames.length];
			for (int i = 0; i < altNames.length; i++)
				genNames[i] = new GeneralName(GeneralName.rfc822Name, new DERIA5String(altNames[i]));
			certBuilder.addExtension(Extension.subjectAlternativeName, access.isCritical(5), new GeneralNames(genNames));
			
			/*		 Basic constraints		*/
			BasicConstraints bc;
			if (access.isCA())
				bc = new BasicConstraints(Integer.parseInt(access.getPathLen()));
			else
				bc = new BasicConstraints(false);
			certBuilder.addExtension(Extension.basicConstraints, access.isCritical(8), bc);
			
			JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(algorithm);
			ContentSigner contentSigner = csBuilder.build((PrivateKey)keystore.getKey(keypair_name, ksPass.toCharArray()));
			X509Certificate	cert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));
			
			CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
			
			List<JcaX509CertificateHolder> chain = new ArrayList<>();
			
			chain.add(new JcaX509CertificateHolder(cert));
			for(Certificate c : keystore.getCertificateChain(keypair_name))
			{
				chain.add(new JcaX509CertificateHolder((X509Certificate)c));
			}
			cmsGenerator.addCertificates(new CollectionStore<JcaX509CertificateHolder>(chain));
			CMSTypedData typedData = new CMSProcessableByteArray(cert.getEncoded());
			CMSSignedData signedData = cmsGenerator.generate(typedData);
			
			FileOutputStream out = new FileOutputStream(file);
			out.write(signedData.getEncoded());
			out.close();
			myCSR = null;
			return true;
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		return false;
	}

}
