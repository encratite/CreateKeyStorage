package createKeyStorage;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class CreateKeyStorage  {
	private static byte[] readFile(String path) throws IOException {
		FileInputStream fileStream = new FileInputStream(path);
		DataInputStream dataStream = new DataInputStream(fileStream);
		byte[] bytes = new byte[dataStream.available()];
		dataStream.readFully(bytes);
		return bytes;
	}

	public static void main(String[] arguments) {
		if(arguments.length != 5) {
			String path = CreateKeyStorage.class.getName();
			System.out.println("Usage: java " + path + " <JKS file> <certificate> <key> <alias> <password>");
			return;
		}
		
		String jksPath = arguments[0];
		String clientCertificatePath = arguments[1];
		String clientKeyPath = arguments[2];
		String alias = arguments[3];
		char[] password = arguments[4].toCharArray();

		try {
			byte[] key = readFile(clientKeyPath);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec keySpecification = new PKCS8EncodedKeySpec(key);
			PrivateKey privateKey = keyFactory.generatePrivate(keySpecification);
			
			List<Certificate> certificates = new ArrayList<Certificate>(); 
			addCertificate(clientCertificatePath, certificates);
			Certificate[] certificateArray = certificates.toArray(new Certificate[certificates.size()]);

			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyStore.load(null, password);
			keyStore.setKeyEntry(alias, privateKey, password, certificateArray);
			keyStore.store(new FileOutputStream(jksPath), password);
		} catch (Exception exception) {
			exception.printStackTrace();
		}
	}
	
	private static void addCertificate(String certificatePath, List<Certificate> output) throws CertificateException, IOException {
		byte[] certificateBytes = readFile(certificatePath);
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		ByteArrayInputStream certificateStream = new ByteArrayInputStream(certificateBytes);
		Collection<? extends Certificate> certificateCollection = certificateFactory.generateCertificates(certificateStream);
		output.addAll(certificateCollection);
	}
}
