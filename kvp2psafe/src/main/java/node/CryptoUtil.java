package node;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Utility class providing cryptographic functionality for a distributed system
 * using RSA, AES/GCM, HMAC-SHA256, TLS, and Shamir Secret Sharing for key
 * distribution between nodes.
 *
 * <p>This class manages:
 * <ul>
 *   <li>Node-specific keystore generation (RSA keypair + certificate).</li>
 *   <li>Global truststore synchronization.</li>
 *   <li>Ephemeral AES and HMAC key creation and reconstruction via shares.</li>
 *   <li>Authenticated encryption using AES/GCM.</li>
 *   <li>Integrity verification with HMAC-SHA256.</li>
 *   <li>Digital signatures (RSA-PSS) and certificate verification.</li>
 *   <li>TLS context initialisation for secure communication.</li>
 * </ul>
 * </p>
 *
 * <p>Keys are never stored persistently. Instead they are distributed using a
 * (threshold = 1, n = 3) Shamir Secret Sharing configuration. Keys are 
 * reconstructed on-demand when needed for cryptographic operations.</p>
 *
 * <p> All methods are thread-safe and synchronized where necessary.</p>
 */
public class CryptoUtil {
	/**
	 * The ID of the current node using this CryptoUtil instance.
	 */
    private static String NODE_ID = null;
    
    /**
     * Filename of the PKCS#12 keystore associated with this node.
     */
    private static String KEYSTORE_FILE = null;
    
    /**
     * Shared PKCS#12 truststore filename.
     */
    private static final String TRUSTSTORE_FILE = "truststore.p12";
    
    /**
     * Password protecting both keystore and truststore files.
     */
    private static final char[] STORE_PASSWORD = "password".toCharArray();
    
    /**
     * Prefix for the RSA key alias stored inside the keystore.
     */
    private static final String RSA_ALIAS_PREFIX = "rsa_";
    
    /**
     * IV length (in bytes) for AES/GCM encryption.
     */
    private static final int GCM_IV_LENGTH = 12;
    
    /**
     * Authentication tag length for AES/GCM encryption.
     */
    private static final int GCM_TAG_LENGTH = 128;

    // Shamir Secret Sharing parameters
    private static final int THRESHOLD = 2;  // Threshold number of shares required to reconstruct a secret key
    private static final int TOTAL_SHARES = 3;  // Total number of shares generated for each secret

    
    private static SecretKey currentAesKey = null;  // Currently loaded AES key reconstructed from shares
    private static SecretKey currentHmacKey = null; // Currently loaded HMAC key reconstructed from shares.

    /**
     * Stores received AES key shares from other nodes.
     */
    private static final Map<String, SecretSharing.Share> receivedAesShares = new HashMap<>();
    
    /**
     * Stores received HMAC key shares from other nodes.
     */
    private static final Map<String, SecretSharing.Share> receivedHmacShares = new HashMap<>();

    /**
     * Reference to the P2PNode instance for requesting shares when needed.
     */
    private static Object p2pNodeRef = null;

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    /**
     * Sets the P2PNode reference for lazy key reconstruction.
     * 
     * @param node The P2PNode instance
     */
    public static synchronized void setP2PNode(Object node) {
        p2pNodeRef = node;
        System.out.println("[CryptoUtil] P2PNode reference set for lazy key reconstruction");
    }

    /**
     * Ensures that keys are reconstructed before performing cryptographic operations.
     * If keys are not available, requests shares from online nodes.
     * 
     * @throws Exception if key reconstruction fails
     */
    private static synchronized void ensureKeysAvailable() throws Exception {
        if (areKeysReconstructed()) {
            return; // Keys already available
        }
        
        System.out.println("[CryptoUtil] Keys not available. Starting lazy reconstruction...");
        
        if (p2pNodeRef == null) {
            throw new IllegalStateException("P2PNode reference not set. Cannot request shares.");
        }
        
        try {
            // Use reflection to call requestSharesFromOnlineNodes
            java.lang.reflect.Method method = p2pNodeRef.getClass()
                .getMethod("requestSharesFromOnlineNodes");
            method.invoke(p2pNodeRef);
            
            // Wait for keys to be reconstructed with timeout
            int maxAttempts = 10;
            int attempt = 0;
            
            while (attempt < maxAttempts && !areKeysReconstructed()) {
                System.out.println("[CryptoUtil] Waiting for keys... (" + (attempt + 1) + "/" + maxAttempts + ")");
                Thread.sleep(1000);
                attempt++;
            }
            
            if (!areKeysReconstructed()) {
                throw new IllegalStateException("Failed to reconstruct keys after " + maxAttempts + " attempts");
            }
            
            System.out.println("[CryptoUtil] Keys successfully reconstructed on-demand");
            
        } catch (Exception e) {
            throw new Exception("Failed to ensure keys are available: " + e.getMessage(), e);
        }
    }

    
    /**
     * Initializes the cryptographic environment for this node.
     *
     * <p>This method:</p>
     * <ul>
     *     <li>Generates or loads the node's PKCS#12 keystore.</li>
     *     <li>Ensures an RSA 2048-bit keypair exists.</li>
     *     <li>Creates a self-signed certificate if missing.</li>
     *     <li>Adds the certificate to the global truststore.</li>
     * </ul>
     *
     * @param nodeId Unique identifier for this node.
     * @throws Exception If keystore, certificate, or truststore operations fail.
     */
    public static synchronized void init(String nodeId) throws Exception {
        NODE_ID = nodeId;
        KEYSTORE_FILE = "keystore_" + nodeId + ".p12";

        // 1) Ensure node keystore exists and contains RSA keypair
        KeyStore nodeKs = KeyStore.getInstance("PKCS12");
        File ksFile = new File(KEYSTORE_FILE);
        if (ksFile.exists()) {
            try (FileInputStream fis = new FileInputStream(ksFile)) {
                nodeKs.load(fis, STORE_PASSWORD);
            }
        } else {
            nodeKs.load(null, null);
        }

        String rsaAlias = RSA_ALIAS_PREFIX + nodeId;

        // Generate RSA keypair + self-signed cert if missing
        if (!nodeKs.containsAlias(rsaAlias)) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();

            Certificate cert = generateSelfSignedCertificate(kp, "CN=" + nodeId);

            nodeKs.setKeyEntry(rsaAlias, kp.getPrivate(), STORE_PASSWORD, new Certificate[] { cert });
            try (FileOutputStream fos = new FileOutputStream(KEYSTORE_FILE)) {
                nodeKs.store(fos, STORE_PASSWORD);
            }
            System.out.println("[CryptoUtil] Created RSA keypair + cert in " + KEYSTORE_FILE);
        }

        // 2) Setup truststore
        setupTruststore(nodeKs, rsaAlias);
    }

    
    /**
     * Stores a received Shamir share (either AES or HMAC) from another node.
     *
     * @param senderNodeId ID of the node that sent the share.
     * @param keyType "AES" or "HMAC".
     * @param shareNumber Numerical index of the share.
     * @param shareData Serialized share data.
     */
    public static synchronized void storeReceivedShare(String senderNodeId, String keyType,
            int shareNumber, String shareData) {
        try {
            SecretSharing.Share share = SecretSharing.Share.deserialize(shareData);

            if ("AES".equals(keyType)) {
                receivedAesShares.put(senderNodeId + "_" + shareNumber, share);
                System.out
                        .println("[CryptoUtil] Stored AES share from " + senderNodeId + " (share " + shareNumber + ")");
            } else if ("HMAC".equals(keyType)) {
                receivedHmacShares.put(senderNodeId + "_" + shareNumber, share);
                System.out.println(
                        "[CryptoUtil] Stored HMAC share from " + senderNodeId + " (share " + shareNumber + ")");
            }
        } catch (Exception e) {
            System.err.println("[CryptoUtil] Error storing share: " + e.getMessage());
        }
    }

    /**
     * Attempts to reconstruct the AES key using collected Shamir shares.
     *
     * @return true if the key was successfully reconstructed.
     */
    public static synchronized boolean reconstructAesKeyFromShares() {
        try {
            if (receivedAesShares.size() >= THRESHOLD) {
                System.out.println("[CryptoUtil] Reconstructing AES key from " + receivedAesShares.size() + " shares");

                // Pegar as primeiras THRESHOLD shares
                SecretSharing.Share[] sharesToUse = new SecretSharing.Share[THRESHOLD];
                int i = 0;
                for (Map.Entry<String, SecretSharing.Share> entry : receivedAesShares.entrySet()) {
                    if (i >= THRESHOLD)
                        break;
                    sharesToUse[i] = entry.getValue();
                    i++;
                }

                BigInteger reconstructedSecret = SecretSharing.combine(sharesToUse);
                currentAesKey = reconstructKeyFromBigInteger(reconstructedSecret, "AES");
                System.out.println("[CryptoUtil] AES key successfully reconstructed");
                return true;
            } else {
                System.out.println("[CryptoUtil] Not enough AES shares available: " +
                        receivedAesShares.size() + "/" + THRESHOLD);
                return false;
            }
        } catch (Exception e) {
            System.err.println("[CryptoUtil] Failed to reconstruct AES key: " + e.getMessage());
            return false;
        }
    }

    
    /**
     * Attempts to reconstruct the HMAC key using collected Shamir shares.
     *
     * @return true if the key was successfully reconstructed.
     */
    public static synchronized boolean reconstructHmacKeyFromShares() {
        try {
            if (receivedHmacShares.size() >= THRESHOLD) {
                System.out
                        .println("[CryptoUtil] Reconstructing HMAC key from " + receivedHmacShares.size() + " shares");

                // Pegar as primeiras THRESHOLD shares
                SecretSharing.Share[] sharesToUse = new SecretSharing.Share[THRESHOLD];
                int i = 0;
                for (Map.Entry<String, SecretSharing.Share> entry : receivedHmacShares.entrySet()) {
                    if (i >= THRESHOLD)
                        break;
                    sharesToUse[i] = entry.getValue();
                    i++;
                }

                BigInteger reconstructedSecret = SecretSharing.combine(sharesToUse);
                currentHmacKey = reconstructKeyFromBigInteger(reconstructedSecret, "HMAC");
                System.out.println("[CryptoUtil] HMAC key successfully reconstructed");
                return true;
            } else {
                System.out.println("[CryptoUtil] Not enough HMAC shares available: " +
                        receivedHmacShares.size() + "/" + THRESHOLD);
                return false;
            }
        } catch (Exception e) {
            System.err.println("[CryptoUtil] Failed to reconstruct HMAC key: " + e.getMessage());
            return false;
        }
    }

    /**
     * Generates a new AES-256 key and splits it into multiple Shamir shares.
     *
     * <p><b> The generated AES key is not stored locally.</b></p>
     *
     * @return Array of Shamir shares to distribute to other nodes.
     * @throws Exception If the AES key cannot be generated or shared.
     */
    public static synchronized SecretSharing.Share[] generateAndSplitAesKey() throws Exception {
        System.out.println("[CryptoUtil] Generating new AES key and splitting into " + TOTAL_SHARES + " shares");

        // Gerar chave AES
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey aesKey = kg.generateKey();

        BigInteger aesKeyBigInt = convertKeyToBigInteger(aesKey);
        SecretSharing.Share[] shares = SecretSharing.share(THRESHOLD - 1, TOTAL_SHARES, aesKeyBigInt);
        receivedAesShares.put("", shares[0]); // Armazenar a primeira share localmente
        // NÃƒO guardar a chave localmente - apenas gerar shares para distribuir
        System.out.println("[CryptoUtil] AES key generated and split (not stored locally)");
        return shares;
    }

    /**
     * Generates a new HMAC key and splits it into Shamir shares.
     *
     * @return Array of Shamir shares to distribute.
     * @throws Exception If key generation or sharing fails.
     */
    public static synchronized SecretSharing.Share[] generateAndSplitHmacKey() throws Exception {
        System.out.println("[CryptoUtil] Generating new HMAC key and splitting into " + TOTAL_SHARES + " shares");

        KeyGenerator kg = KeyGenerator.getInstance("HmacSHA256");
        kg.init(256);
        SecretKey hmacKey = kg.generateKey();

        BigInteger hmacKeyBigInt = convertKeyToBigInteger(hmacKey);
        SecretSharing.Share[] shares = SecretSharing.share(THRESHOLD - 1, TOTAL_SHARES, hmacKeyBigInt);
        receivedHmacShares.put("", shares[0]); // Armazenar a primeira share localmente

        System.out.println("[CryptoUtil] HMAC key generated and split (not stored locally)");
        return shares;
    }

    /**
     * Retrieves all AES Shamir secret shares currently stored by this node that may
     * be relevant to the requesting node.
     *
     * <p>Note: Since this node does not store metadata linking shares to specific
     * requesters, this method returns <b>all AES shares</b> it possesses. The caller
     * (e.g., P2PServer) is responsible for determining which shares should actually
     * be forwarded to the requester.</p>
     *
     * @param requesterNodeId The ID of the node requesting AES key shares.
     * @return A map containing all AES secret shares stored by this node. Keys follow
     *         the format {@code "senderNodeId_shareNumber"}.
     */
    public static synchronized Map<String, SecretSharing.Share> getAesSharesForRequester(String requesterNodeId) {
        Map<String, SecretSharing.Share> result = new HashMap<>();

        // Procurar shares que pertencem ao requester (formato:
        // requesterNodeId_shareNumber)
        for (Map.Entry<String, SecretSharing.Share> entry : receivedAesShares.entrySet()) {
            String key = entry.getKey();
            // A chave Ã© no formato "senderNodeId_shareNumber"
            // Precisamos verificar se a share pertence ao requester
            // Como nÃ£o temos essa informaÃ§Ã£o, retornamos todas as shares AES que temos
            // O P2PServer vai filtrar quais enviar
            result.put(key, entry.getValue());
        }

        System.out.println("[CryptoUtil] Found " + result.size() + " AES shares for requester " + requesterNodeId);
        return result;
    }

    /**
     * Retrieves all HMAC Shamir secret shares currently stored by this node that may
     * be relevant to the requesting node.
     *
     * <p>Since shares are not tagged with requester metadata, this method returns
     * <b>all HMAC shares</b> available in the local store. Higher layers of the
     * application determine which shares should be sent to the requester.</p>
     *
     * @param requesterNodeId The ID of the node requesting HMAC key shares.
     * @return A map containing all HMAC secret shares stored by this node. Keys follow
     *         the format {@code "senderNodeId_shareNumber"}.
     */
    public static synchronized Map<String, SecretSharing.Share> getHmacSharesForRequester(String requesterNodeId) {
        Map<String, SecretSharing.Share> result = new HashMap<>();

        for (Map.Entry<String, SecretSharing.Share> entry : receivedHmacShares.entrySet()) {
            String key = entry.getKey();
            result.put(key, entry.getValue());
        }

        System.out.println("[CryptoUtil] Found " + result.size() + " HMAC shares for requester " + requesterNodeId);
        return result;
    }

    /**
     * Ensures that the node's self-signed certificate is present in the shared
     * truststore used for mutual TLS authentication between nodes.
     *
     * <p>This method will:</p>
     * <ul>
     *     <li>Load or create the truststore.</li>
     *     <li>Retrieve this node's certificate from its keystore.</li>
     *     <li>Add the certificate to the truststore if not already present.</li>
     *     <li>Persist the updated truststore to disk.</li>
     * </ul>
     *
     * @param nodeKs   The keystore for this node, containing its RSA keypair.
     * @param rsaAlias The alias under which the RSA certificate is stored.
     *
     * @throws Exception If the certificate is missing, or if truststore update fails.
     */
    private static void setupTruststore(KeyStore nodeKs, String rsaAlias) throws Exception {
        KeyStore trustKs = KeyStore.getInstance("PKCS12");
        File trustFile = new File(TRUSTSTORE_FILE);
        if (trustFile.exists()) {
            try (FileInputStream fis = new FileInputStream(trustFile)) {
                trustKs.load(fis, STORE_PASSWORD);
            }
        } else {
            trustKs.load(null, null);
        }

        Certificate myCert = nodeKs.getCertificate(rsaAlias);
        if (myCert == null) {
            throw new IllegalStateException("Certificate not found after creation!");
        }

        String trustAlias = "cert_" + NODE_ID;
        if (!trustKs.containsAlias(trustAlias)) {
            trustKs.setCertificateEntry(trustAlias, myCert);
            try (FileOutputStream fos = new FileOutputStream(TRUSTSTORE_FILE)) {
                trustKs.store(fos, STORE_PASSWORD);
            }
            System.out.println("[CryptoUtil] Added cert to truststore");
        }
    }

    /**
     * Loads this node's RSA private key from its PKCS#12 keystore.
     *
     * @return The RSA {@link PrivateKey}.
     *
     * @throws IllegalStateException If {@code CryptoUtil.init()} has not been called.
     * @throws Exception If the keystore file cannot be loaded or the key is missing.
     */
    private static PrivateKey getRsaPrivateKey() throws Exception {
        if (NODE_ID == null)
            throw new IllegalStateException("CryptoUtil not initialized");
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(KEYSTORE_FILE)) {
            ks.load(fis, STORE_PASSWORD);
        }
        String rsaAlias = RSA_ALIAS_PREFIX + NODE_ID;
        return (PrivateKey) ks.getKey(rsaAlias, STORE_PASSWORD);
    }

    /**
     * Retrieves this node's X.509 certificate from its keystore.
     *
     * @return The {@link Certificate} associated with this node.
     *
     * @throws IllegalStateException If {@code CryptoUtil.init()} has not been called.
     * @throws Exception If the keystore cannot be loaded or no certificate is found.
     */
    private static Certificate getCertificate() throws Exception {
        if (NODE_ID == null)
            throw new IllegalStateException("CryptoUtil not initialized");
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(KEYSTORE_FILE)) {
            ks.load(fis, STORE_PASSWORD);
        }
        String rsaAlias = RSA_ALIAS_PREFIX + NODE_ID;
        return ks.getCertificate(rsaAlias);
    }

    /**
     * Returns the reconstructed AES secret key for symmetric encryption.
     * Triggers lazy key reconstruction if keys are not yet available.
     *
     * @return The AES {@link SecretKey}.
     *
     * @throws IllegalStateException If the AES key cannot be reconstructed.
     */
    private static SecretKey getSecretKey() throws Exception {
        ensureKeysAvailable();
        
        if (currentAesKey == null) {
            throw new IllegalStateException("AES key not available after reconstruction attempt");
        }
        return currentAesKey;
    }

    /**
     * Returns the reconstructed HMAC-SHA256 secret key.
     * Triggers lazy key reconstruction if keys are not yet available.
     *
     * @return The HMAC {@link SecretKey}.
     *
     * @throws IllegalStateException If the HMAC key cannot be reconstructed.
     */
    private static SecretKey getHmacSecretKey() throws Exception {
        ensureKeysAvailable();
        
        if (currentHmacKey == null) {
            throw new IllegalStateException("HMAC key not available after reconstruction attempt");
        }
        return currentHmacKey;
    }

    /**
     * Creates and initializes a fully configured {@link SSLContext} for secure
     * communication between nodes using mutually authenticated TLS.
     *
     * <p>The SSL context uses:</p>
     * <ul>
     *     <li>This node's RSA private key and certificate (from keystore).</li>
     *     <li>All trusted certificates stored in the global truststore.</li>
     *     <li>TLSv1.3 if available, otherwise TLSv1.2.</li>
     *     <li>Strong cipher suites (AES-256-GCM).</li>
     * </ul>
     *
     * @return A configured {@link SSLContext} for secure connections.
     *
     * @throws IllegalStateException If the utility has not been initialized.
     * @throws Exception If keystore or truststore loading fails, or if TLS
     *                   initialization fails.
     */
    public static synchronized SSLContext getSSLContext() throws Exception {
        if (NODE_ID == null)
            throw new IllegalStateException("CryptoUtil not initialized");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(KEYSTORE_FILE)) {
            keyStore.load(fis, STORE_PASSWORD);
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, STORE_PASSWORD);

        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(TRUSTSTORE_FILE)) {
            trustStore.load(fis, STORE_PASSWORD);
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(trustStore);

        SSLContext sc;
        try {
            sc = SSLContext.getInstance("TLSv1.3");
        } catch (NoSuchAlgorithmException e) {
            sc = SSLContext.getInstance("TLSv1.2");
        }

        sc.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

        SSLParameters params = sc.getDefaultSSLParameters();
        params.setProtocols(new String[] { "TLSv1.3" });
        params.setCipherSuites(new String[] { "TLS_AES_256_GCM_SHA384" });
        sc.getDefaultSSLParameters().setUseCipherSuitesOrder(true);

        return sc;
    }

    /**
     * Container class representing the output of an AES/GCM encryption operation.
     *
     * <p>It holds:</p>
     * <ul>
     *     <li>{@code encryptedData} â€" the ciphertext including the GCM auth tag</li>
     *     <li>{@code iv} â€" the random initialization vector used during encryption</li>
     * </ul>
     */
    public static class EncryptionResult {
    	
    	/**
         * The encrypted ciphertext including the authentication tag.
         */
        public final byte[] encryptedData;
        
        /**
         * The AES/GCM initialization vector used during encryption.
         */
        public final byte[] iv;

        /**
         * Creates a new encryption result.
         *
         * @param encryptedData The encrypted payload.
         * @param iv            The Initialization Vector used during AES/GCM encryption.
         */
        public EncryptionResult(byte[] encryptedData, byte[] iv) {
            this.encryptedData = encryptedData;
            this.iv = iv;
        }
    }

    
    /**
     * Encrypts plaintext using AES/GCM with the reconstructed AES key.
     * Keys are reconstructed on-demand if not available.
     *
     * @param plaintext The plaintext string to encrypt.
     * @return The encrypted data and IV.
     * @throws Exception If the AES key cannot be reconstructed or cipher initialization fails.
     */
    public static EncryptionResult encrypt(String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(), spec);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));
        return new EncryptionResult(encrypted, iv);
    }

    /**
     * Decrypts AES/GCM ciphertext using the reconstructed AES key.
     * Keys are reconstructed on-demand if not available.
     *
     * @param ciphertext The encrypted byte array.
     * @param iv The initialization vector used during encryption.
     * @return The decrypted plaintext.
     * @throws Exception If keys cannot be reconstructed or decryption/authentication fails.
     */
    public static String decrypt(byte[] ciphertext, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), spec);
        byte[] decrypted = cipher.doFinal(ciphertext);
        return new String(decrypted, "UTF-8");
    }

    /**
     * Computes an HMAC-SHA256 authentication tag for the provided data.
     * Keys are reconstructed on-demand if not available.
     *
     * @param data Input to authenticate.
     * @return Byte array containing the computed HMAC.
     * @throws Exception If keys cannot be reconstructed or HMAC computation fails.
     */
    public static byte[] computeHmac(String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(getHmacSecretKey());
        return mac.doFinal(data.getBytes("UTF-8"));
    }

    /**
     * Verifies an HMAC tag.
     * Keys are reconstructed on-demand if not available.
     *
     * @param data The data that was MACed.
     * @param hmac The expected HMAC value.
     * @return true if valid, false otherwise.
     * @throws Exception If keys cannot be reconstructed or verification fails.
     */
    public static boolean verifyHmac(String data, byte[] hmac) throws Exception {
        byte[] computed = computeHmac(data);
        return MessageDigest.isEqual(hmac, computed);
    }

    /**
     * Converts a byte array to a lowercase hexadecimal string.
     *
     * @param bytes Input byte array.
     * @return Hexadecimal representation.
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /**
     * Signs data using RSA-PSS with SHA-256.
     *
     * @param data The data to sign.
     * @return Base64-encoded signature.
     */
    public static String sign(String data) throws Exception {
        System.out.println("[CryptoUtil] Signing data: " + data);
        Signature sig = Signature.getInstance("SHA256withRSA/PSS");
        sig.initSign(getRsaPrivateKey());
        sig.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] signature = sig.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    /**
     * Retrieves this node's certificate encoded in Base64.
     *
     * @return Base64-encoded certificate.
     */
    public static String getCertificateBase64() throws Exception {
        Certificate cert = getCertificate();
        return Base64.getEncoder().encodeToString(cert.getEncoded());
    }

    /**
     * Verifies a signature using a provided Base64 certificate.
     *
     * @param data Original data.
     * @param signatureBase64 Base64-encoded signature.
     * @param certBase64 Base64-encoded X.509 certificate.
     * @return true if signature is valid.
     */
    public static boolean verify(String data, String signatureBase64, String certBase64) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        byte[] certBytes = Base64.getDecoder().decode(certBase64.trim());
        Certificate cert = cf.generateCertificate(new ByteArrayInputStream(certBytes));
        PublicKey pk = cert.getPublicKey();

        Signature sig = Signature.getInstance("SHA256withRSA/PSS");
        sig.initVerify(pk);
        sig.update(data.getBytes(StandardCharsets.UTF_8));
        return sig.verify(Base64.getDecoder().decode(signatureBase64.trim()));
    }

    /**
     * Generates a new self-signed X.509 certificate for the provided RSA key pair.
     *
     * <p>The certificate uses:</p>
     * <ul>
     *     <li>SHA-256 with RSA signature</li>
     *     <li>10-year validity period</li>
     *     <li>The same distinguished name (DN) for issuer and subject</li>
     * </ul>
     *
     * @param keyPair The RSA keypair for which the certificate will be generated.
     * @param dn      The distinguished name (subject/issuer).
     * @return A self-signed {@link Certificate}.
     *
     * @throws Exception If certificate building or signing fails.
     */
    private static Certificate generateSelfSignedCertificate(KeyPair keyPair, String dn) throws Exception {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        X500Name dnName = new X500Name(dn);
        BigInteger certSerialNumber = new BigInteger(Long.toString(now));
        Date endDate = new Date(now + (10L * 365 * 24 * 60 * 60 * 1000));

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .build(keyPair.getPrivate());

        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certBuilder.build(contentSigner));
    }

    /**
     * Converts a {@link SecretKey} into a {@link BigInteger} suitable for use with
     * Shamir Secret Sharing.
     *
     * <p>The key bytes are treated as an unsigned integer.</p>
     *
     * @param key The secret key to convert.
     * @return A BigInteger representing the key.
     */
    private static BigInteger convertKeyToBigInteger(SecretKey key) {
        byte[] keyBytes = key.getEncoded();
        return new BigInteger(1, keyBytes);
    }

    /**
     * Reconstructs a {@link SecretKey} from a BigInteger previously generated via
     * Shamir Secret Sharing.
     *
     * <p>This method normalizes the byte array to exactly 32 bytes, padding or
     * trimming as necessary, then rebuilds the appropriate key type:</p>
     *
     * <ul>
     *     <li>{@code "AES"} → AES-256 key</li>
     *     <li>{@code "HMAC"} → HMAC-SHA256 key</li>
     * </ul>
     *
     * @param secret  The BigInteger representing the recovered secret.
     * @param keyType Either {@code "AES"} or {@code "HMAC"}.
     * @return A reconstructed {@link SecretKey}.
     */
    private static SecretKey reconstructKeyFromBigInteger(BigInteger secret, String keyType) {
        byte[] keyBytes = secret.toByteArray();

        if (keyBytes.length > 32) {
            byte[] trimmed = new byte[32];
            System.arraycopy(keyBytes, keyBytes.length - 32, trimmed, 0, 32);
            keyBytes = trimmed;
        } else if (keyBytes.length < 32) {
            byte[] padded = new byte[32];
            System.arraycopy(keyBytes, 0, padded, 32 - keyBytes.length, keyBytes.length);
            keyBytes = padded;
        }

        if ("AES".equals(keyType)) {
            return new SecretKeySpec(keyBytes, "AES");
        } else {
            return new SecretKeySpec(keyBytes, "HmacSHA256");
        }
    }

    /**
     * Checks whether both AES and HMAC keys have been reconstructed.
     *
     * @return true if both keys are available.
     */
    public static synchronized boolean areKeysReconstructed() {
        return currentAesKey != null && currentHmacKey != null;
    }

}