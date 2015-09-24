package com.example.certs;

/**
 * Originally posted at: (not available now)
 * http://blogs.sun.com/andreas/resource/InstallCert.java
 * Use:
 * java InstallCert hostname
 * Example:
 *% java InstallCert ecc.fedora.redhat.com
 */

import javax.net.ssl.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Class used to add the server's certificate to the KeyStore with your trusted
 * certificates.
 */
public final class InstallCert {
	private static final Logger logger = LoggerFactory
			.getLogger(InstallCert.class);
	private static final int ARGS_LENGTH = 4;
	private static final char SEP = File.separatorChar;

	private InstallCert() {

	}

	public static void main(final String[] args) throws Exception {
		String host;
		int port;
		char[] passphrase;
		String certFile, outputFile;

		if (args.length == ARGS_LENGTH) {
			String[] c = args[0].split(":");
			host = c[0];
			port = (c.length == 1) ? 443 : Integer.parseInt(c[1]);
			String p = args[2];
			passphrase = p.toCharArray();
			certFile = args[1];
			outputFile = args[3];
		} else {
			logger.info("Usage: java InstallCert <host>[:port] <certFile> <pass> <outputFile>");
			return;
		}

		File file = new File(certFile);
		if (!file.isFile()) {
			logger.error("Specified cert not found: {}", file);

			File dir = new File(System.getProperty("java.home") + SEP + "lib"
					+ SEP + "security");
			logger.info("Using default bundled at " + dir);
			file = new File(dir, "jssecacerts");
			if (!file.isFile()) {
				file = new File(dir, "cacerts");
			}
		}
		logger.debug("Loading KeyStore " + file + "...");
		InputStream in = new FileInputStream(file);
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(in, passphrase);
		in.close();

		SSLContext context = SSLContext.getInstance("TLS");
		TrustManagerFactory tmf = TrustManagerFactory
				.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(ks);
		X509TrustManager defaultTrustManager = (X509TrustManager) tmf
				.getTrustManagers()[0];
		SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
		context.init(null, new TrustManager[] { tm }, null);
		SSLSocketFactory factory = context.getSocketFactory();

		logger.debug("Opening connection to " + host + ":" + port + "...");
		SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
		socket.setSoTimeout(10000);
		try {
			logger.debug("Starting SSL handshake...");
			socket.startHandshake();
			socket.close();
			logger.debug("No errors, certificate is already trusted");
		} catch (SSLException e) {
			logger.error("Error during handshake", e);
		}

		X509Certificate[] chain = tm.chain;
		if (chain == null) {
			logger.debug("Could not obtain server certificate chain");
			return;
		}

		BufferedReader reader = new BufferedReader(new InputStreamReader(
				System.in));

		System.out.println();
		System.out.println("Server sent " + chain.length + " certificate(s):");
		System.out.println();
		MessageDigest sha1 = MessageDigest.getInstance("SHA1");
		MessageDigest md5 = MessageDigest.getInstance("MD5");
		for (int i = 0; i < chain.length; i++) {
			X509Certificate cert = chain[i];
			System.out.println(" " + (i + 1) + " Subject "
					+ cert.getSubjectDN());
			System.out.println("   Issuer  " + cert.getIssuerDN());
			sha1.update(cert.getEncoded());
			System.out.println("   sha1    " + toHexString(sha1.digest()));
			md5.update(cert.getEncoded());
			System.out.println("   md5     " + toHexString(md5.digest()));
			System.out.println();
		}

		System.out
				.println("Enter certificate to add to trusted keystore or 'q' to quit: [1]");
		String line = reader.readLine().trim();
		int k;
		try {
			k = (line.length() == 0) ? 0 : Integer.parseInt(line) - 1;
		} catch (NumberFormatException e) {
			System.out.println("KeyStore not changed");
			return;
		}

		X509Certificate cert = chain[k];
		String alias = host + "-" + (k + 1);
		ks.setCertificateEntry(alias, cert);

		OutputStream out = new FileOutputStream(outputFile);
		ks.store(out, passphrase);
		out.close();

		System.out.println(cert);
		logger.info("Added certificate to keystore {} using alias '{}'",
				outputFile, alias);
	}

	private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();

	private static String toHexString(final byte[] bytes) {
		StringBuilder sb = new StringBuilder(bytes.length * 3);
		for (int b : bytes) {
			b &= 0xff;
			sb.append(HEXDIGITS[b >> 4]);
			sb.append(HEXDIGITS[b & 15]);
			sb.append(' ');
		}
		return sb.toString();
	}

	private static class SavingTrustManager implements X509TrustManager {

		private final X509TrustManager tm;
		private X509Certificate[] chain;

		SavingTrustManager(final X509TrustManager tm) {
			this.tm = tm;
		}

		public X509Certificate[] getAcceptedIssuers() {
			return new X509Certificate[0];
		}

		public void checkClientTrusted(final X509Certificate[] chain,
				final String authType) throws CertificateException {
			throw new UnsupportedOperationException();
		}

		public void checkServerTrusted(final X509Certificate[] chain,
				final String authType) throws CertificateException {
			this.chain = chain;
			tm.checkServerTrusted(chain, authType);
		}
	}

}