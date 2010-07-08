package createKeyStorage;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
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
		if(arguments.length != 6) {
			String path = CreateKeyStorage.class.getName();
			System.out.println("Usage: java " + path + " <JKS file> <CA> <certificate> <key> <alias> <password>");
			return;
		}
		
		String jksPath = arguments[0];
		String certificateAuthorityPath = arguments[1];
		String clientCertificatePath = arguments[2];
		String clientKeyPath = arguments[3];
		String alias = arguments[4];
		char[] password = arguments[5].toCharArray();

		try {
			byte[] key = readFile(clientKeyPath);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec keySpecification = new PKCS8EncodedKeySpec(key);
			PrivateKey privateKey = keyFactory.generatePrivate(keySpecification);

			String[] certificatePaths = {
				certificateAuthorityPath,
				clientCertificatePath
			};
			
			List<Certificate> certificates = new ArrayList<Certificate>(); 
			for(String certificatePath : certificatePaths) {
				byte[] certificateBytes = readFile(certificatePath);
				CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
				ByteArrayInputStream certificateStream = new ByteArrayInputStream(certificateBytes);
				Collection<? extends Certificate> certificateCollection = certificateFactory.generateCertificates(certificateStream);
				certificates.addAll(certificateCollection);
			}
			Certificate[] certificateArray = certificates.toArray(new Certificate[certificates.size()]);

			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyStore.load(null, password);
			keyStore.setKeyEntry(alias, privateKey, password, certificateArray);
			keyStore.store(new FileOutputStream(jksPath), password);
		} catch (Exception exception) {
			exception.printStackTrace();
		}
	}
}
