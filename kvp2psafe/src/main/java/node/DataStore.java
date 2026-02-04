package node;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import node.CashSSE.Client;

/**
 * DataStore is a secure local storage layer used by each P2P node.
 *
 * It supports:
 * - Multiple logical tables (ConcurrentHashMap-backed)
 * - Versioned entries with timestamps
 * - AES encryption + IV + HMAC integrity
 * - Digital signatures for origin authentication
 * - SSE (Searchable Symmetric Encryption) index updates
 * - Integration with P2PNode for replication and cluster coordination
 *
 * Tables store VersionedValue objects, which include encrypted data,
 * metadata, origin information, signatures and timestamps.
 *
 * The DataStore also supports plaintext tables such as "_system_online_nodes".
 */
public class DataStore {

    /**
     * Listener interface used to notify external components (UI, controllers)
     * when a table changes.
     */
    public interface DataChangeListener {
        void onDataChanged(String tableName);
    }

    private DataChangeListener listener;
    private final Map<String, Map<String, VersionedValue>> tables = new ConcurrentHashMap<>();
    private final Set<String> recentPuts = ConcurrentHashMap.newKeySet();
    private P2PNode p2pNode;
    private Client sseClient; // Generates SSE update tokens

    public DataStore() {
        // Create default global table
        tables.put("global", new ConcurrentHashMap<>());
    }

    /** Assigns the SSE client used to generate update/search tokens. */
    public void setSSEClient(Client sseClient) {
        this.sseClient = sseClient;
    }

    /** Injects the P2PNode for replication and distributed events. */
    public void setP2PNode(P2PNode p2pNode) {
        this.p2pNode = p2pNode;
    }

    /** Sets a listener that will be notified when table contents change. */
    public void setListener(DataChangeListener listener) {
        this.listener = listener;
    }

    /**
     * Represents a stored value inside a table.
     *
     * Each value includes:
     * - encrypted value (or plaintext if IV == null)
     * - timestamp (Lamport-style versioning)
     * - IV for AES/CBC
     * - HMAC for integrity (null for plaintext tables)
     * - Origin ID and certificate/signature for authenticity validation
     */
    public static class VersionedValue {
        public final String key;
        public final byte[] encryptedValue;
        public final long timestamp;
        public final byte[] iv;
        public final byte[] hmac;
        public final String originId;
        public final String originCertBase64;
        public final String originSignatureBase64;

        VersionedValue(String key, byte[] encryptedValue, long timestamp, byte[] iv, byte[] hmac,
                String originId, String originCertBase64, String originSignatureBase64) {
            this.key = key;
            this.encryptedValue = encryptedValue;
            this.timestamp = timestamp;
            this.iv = iv;
            this.hmac = hmac;
            this.originId = originId;
            this.originCertBase64 = originCertBase64;
            this.originSignatureBase64 = originSignatureBase64;
        }

        /**
         * Decrypts the value, verifies HMAC integrity, and checks origin signature.
         *
         * @return The decrypted plaintext value.
         * @throws Exception If HMAC or signature validation fails.
         */
        public String getDecryptedValue() throws Exception {

            // Plaintext table: ignore IV and HMAC
            if (iv == null) {
                return new String(encryptedValue, "UTF-8");
            }

            // Validate local integrity (HMAC)
            String dataToVerifyHmac = CryptoUtil.bytesToHex(encryptedValue) + ":" + timestamp;
            if (!CryptoUtil.verifyHmac(dataToVerifyHmac, hmac)) {
                throw new SecurityException("HMAC verification failed: Data tampered locally");
            }

            // Decrypt encrypted value
            String plaintext = CryptoUtil.decrypt(encryptedValue, iv);

            // Validate origin digital signature (authenticity)
            if (originSignatureBase64 != null && originCertBase64 != null) {
                String dataSigned = key + ":" + plaintext + ":" + timestamp;
                boolean ok = CryptoUtil.verify(dataSigned, originSignatureBase64, originCertBase64);
                if (!ok) {
                    throw new SecurityException("Origin signature verification failed: Data tampered or wrong origin");
                }
            }

            return plaintext;
        }
    }

    /**
     * Creates a new table.
     *
     * @param tableName The name of the table to create.
     * @return True if creation succeeded, false if the table already exists.
     */
    public synchronized boolean createTable(String tableName) {
        if (tables.containsKey(tableName)) {
            return false; // Table already exists
        }
        tables.put(tableName, new ConcurrentHashMap<>());
        System.out.println("[DataStore] Created table: " + tableName);
        return true;
    }

    /** @return Set of all table names. */
    public Set<String> getTableNames() {
        return tables.keySet();
    }

    /**
     * Stores an encrypted value with a timestamp and origin metadata.
     * Updates SSE index and notifies listeners.
     *
     * @return True if the PUT was applied; false if ignored (old timestamp or
     *         duplicate).
     */
    public synchronized boolean putWithTimestampAndOrigin(String tableName, String key, String plaintext,
            long timestamp, String originId, String originCertBase64, String originSignatureBase64) {

        if (!tables.containsKey(tableName)) {
            System.out.println("[DataStore] Table '" + tableName + "' does not exist - ignoring PUT");
            return false;
        }

        String uid = tableName + ":" + key + ":" + timestamp + ":" + originId;
        if (recentPuts.contains(uid))
            return false;

        try {
            // Special-case: plaintext system table
            if (tableName.equals("_system_online_nodes")) {
                return putWithTimestampAndOriginPlaintext(tableName, key, plaintext, timestamp,
                        originId, originCertBase64, originSignatureBase64);
            }

            // Encrypt value
            CryptoUtil.EncryptionResult result = CryptoUtil.encrypt(plaintext);
            String dataToSign = CryptoUtil.bytesToHex(result.encryptedData) + ":" + timestamp;
            byte[] hmac = CryptoUtil.computeHmac(dataToSign);

            Map<String, VersionedValue> table = tables.get(tableName);
            VersionedValue existing = table.get(key);

            // Compare timestamps (last-write-wins)
            if (existing == null || timestamp > existing.timestamp) {

                // Store new updated value
                table.put(key, new VersionedValue(key, result.encryptedData, timestamp, result.iv, hmac, originId,
                        originCertBase64, originSignatureBase64));

                // Update SSE searchable index
                if (sseClient != null && p2pNode != null) {
                    // docId como "tableName:key"
                    String docId = tableName;
                    try {
                        sseClient.update(key, docId); // update envia para o servidor local internamente
                        System.out.println("[DataStore] SSE Index updated for key: " + key + " in table: " + tableName);
                    } catch (Exception e) {
                        System.err.println("[DataStore] Failed to update SSE index: " + e.getMessage());
                    }

                }
                System.out.println("[DataStore] Updated " + key + " in table '" + tableName + "' @" + timestamp
                        + " origin=" + originId);
                if (listener != null)
                    listener.onDataChanged(tableName);
            } else {
                System.out.println("[DataStore] Ignored older PUT for " + key + " in table '" + tableName + "'");
            }

            recentPuts.add(uid);
            return true;
        } catch (Exception e) {
            System.err.println("[DataStore] Failed to encrypt/compute HMAC or store: " + e.getMessage());
            return false;
        }
    }

    /**
     * Convenience method used for local writes.
     * Signs the plaintext and delegates to putWithTimestampAndOrigin().
     */
    public synchronized boolean putWithTimestamp(String tableName, String key, String plaintext, long timestamp,
            String originId) {
        try {
            String dataToSign = key + ":" + plaintext + ":" + timestamp;
            String signatureBase64 = CryptoUtil.sign(dataToSign);
            String certBase64 = CryptoUtil.getCertificateBase64();
            return putWithTimestampAndOrigin(tableName, key, plaintext, timestamp, originId, certBase64,
                    signatureBase64);
        } catch (Exception e) {
            System.err.println("[DataStore] Failed to sign or store local put: " + e.getMessage());
            return false;
        }
    }

    /** Retrieves and decrypts the value for a specific key. */
    public synchronized String get(String tableName, String key) {
        Map<String, VersionedValue> table = tables.get(tableName);
        if (table == null)
            return null;

        VersionedValue v = table.get(key);
        if (v == null)
            return null;

        try {
            return v.getDecryptedValue();
        } catch (Exception e) {
            System.err.println("[DataStore] Failed to decrypt or verify: " + e.getMessage());
            return null;
        }
    }

    /** Returns the timestamp of a specific key, or -1 if not found. */
    public synchronized long getTimestamp(String tableName, String key) {
        Map<String, VersionedValue> table = tables.get(tableName);
        if (table == null)
            return -1;

        VersionedValue v = table.get(key);
        return v == null ? -1 : v.timestamp;
    }

    /** Returns all key-value entries from a table. */
    public Map<String, VersionedValue> getAll(String tableName) {
        Map<String, VersionedValue> table = tables.get(tableName);
        return table != null ? table : new ConcurrentHashMap<>();
    }

    /** Returns the entire DataStore contents (all tables). */
    public Map<String, Map<String, VersionedValue>> getAllTables() {
        return tables;
    }

    /** Deletes a key from a table. */
    public void delete(String tableName, String key) {
        Map<String, VersionedValue> table = tables.get(tableName);
        if (table != null) {
            VersionedValue removed = table.remove(key);
            if (removed != null) {
                System.out.println("[DataStore] Deleted " + key + " from table '" + tableName + "'");
                listener.onDataChanged(tableName);
            }
        }
    }

    /**
     * Stores a plaintext (non-encrypted) value with timestamp and origin metadata.
     * Used for system tables such as "_system_online_nodes".
     */
    public synchronized boolean putWithTimestampAndOriginPlaintext(String tableName, String key, String plaintext,
            long timestamp, String originId, String originCertBase64, String originSignatureBase64) {

        if (!tables.containsKey(tableName)) {
            System.out.println("[DataStore] Table '" + tableName + "' does not exist - ignoring PUT");
            return false;
        }

        String uid = tableName + ":" + key + ":" + timestamp + ":" + originId;
        if (recentPuts.contains(uid))
            return false;

        try {
            // Convert plaintext to bytes without encryption
            byte[] valueBytes = plaintext.getBytes("UTF-8");

            Map<String, VersionedValue> table = tables.get(tableName);
            VersionedValue existing = table.get(key);

            if (existing == null || timestamp > existing.timestamp) {
                // Store with null IV since no encryption, null HMAC since no HMAC verification
                table.put(key, new VersionedValue(key, valueBytes, timestamp,
                        null, // No IV needed
                        null, // No HMAC needed
                        originId, originCertBase64, originSignatureBase64));
                System.out.println(
                        "[DataStore] Updated (plaintext) " + key + " in table '" + tableName + "' @" + timestamp
                                + " origin=" + originId);
                if (listener != null)
                    listener.onDataChanged(tableName);
            } else {
                System.out.println("[DataStore] Ignored older PUT for " + key + " in table '" + tableName + "'");
            }

            // Notify P2PNode when enough online nodes exist
            Map<String, VersionedValue> onlineNodesTable = tables.get("_system_online_nodes");

            if (onlineNodesTable != null && onlineNodesTable.size() >= 2) {
                System.out.println("[DataStore] Online nodes table has " +
                        onlineNodesTable.size() + " entries. Notifying P2PNode...");

                if (p2pNode != null) {
                    new Thread(() -> {
                        p2pNode.onOnlineNodesUpdated();
                    }).start();
                }
            }

            recentPuts.add(uid);
            return true;
        } catch (Exception e) {
            System.err.println("[DataStore] Failed to store plaintext: " + e.getMessage());
            return false;
        }
    }
}