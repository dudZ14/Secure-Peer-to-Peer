package node;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

/**
 * P2PServer represents a threaded SSL/TLS server that handles incoming
 * peer-to-peer connections and processes various commands.
 * 
 * This server is responsible for:
 * 1. Handling PUT, DELETE, and SYNC operations for data synchronization
 * 2. Managing secret share distribution and requests for key reconstruction
 * 3. Processing searchable symmetric encryption (SSE) search requests
 * 4. Maintaining document ID mappings for SSE
 * 5. Propagating operations to other peers (excluding the origin)
 * 
 * The server runs in its own thread and handles multiple client connections
 * concurrently using thread-per-connection model.
 * 
 * @see P2PNode
 * @see DataStore
 * @see CryptoUtil
 * @see SecretSharing
 * @see CashSSE
 */
public class P2PServer extends Thread {

    /** Port number on which the server listens */
    private final int port;

    /** Data store instance for persistence */
    private final DataStore dataStore;

    /** Parent P2PNode for callbacks and propagation */
    private final P2PNode parentNode;

    /** Flag indicating whether the server is running */
    private volatile boolean running = true;

    /** SSL server socket for accepting connections */
    private SSLServerSocket serverSocket;

    /** Callback to invoke when port is already in use */
    private Runnable onPortInUse;

    /**
     * HashMap to store received AES shares.
     * Key format: senderNodeId_AES_shareNumber
     */
    private final Map<String, SecretSharing.Share> receivedSharesAES = new HashMap<>();

    /**
     * HashMap to store received HMAC shares.
     * Key format: senderNodeId_HMAC_shareNumber
     */
    private final Map<String, SecretSharing.Share> receivedSharesHMAC = new HashMap<>();

    /**
     * Maps integer document IDs (used by CashSSE) to string keys in format
     * "tableName:key" for reverse lookup of search results.
     */
    private final Map<Integer, String> sseDocIdToKey = new ConcurrentHashMap<>();

    /**
     * Adds a mapping from SSE document ID to the actual key string.
     * This is called by DataStore when indexing documents for SSE.
     * 
     * @param docId       integer document ID used by CashSSE
     * @param docIdString string key in format "tableName:key"
     */
    public void addDocumentMapping(int docId, String docIdString) {
        sseDocIdToKey.put(docId, docIdString);
    }

    /**
     * Adds a mapping from SSE document ID to the actual key string.
     * This is called by DataStore when indexing documents for SSE.
     * 
     * @param docId       integer document ID used by CashSSE
     * @param docIdString string key in format "tableName:key"
     */
    public P2PServer(int port, DataStore dataStore, P2PNode parentNode) {
        this.port = port;
        this.dataStore = dataStore;
        this.parentNode = parentNode;
        setDaemon(true);
    }

    /**
     * Sets a callback to be invoked when the server port is already in use.
     * This allows the parent node to handle port conflicts gracefully.
     * 
     * @param callback the Runnable to execute when port is in use
     */
    public void setOnPortInUse(Runnable callback) {
        this.onPortInUse = callback;
    }

    /**
     * Main server thread execution method.
     * Initializes SSL context, creates server socket, and continuously
     * accepts client connections, spawning a new thread for each.
     */
    @Override
    public void run() {
        try {

            SSLContext sc = CryptoUtil.getSSLContext();
            SSLServerSocketFactory ssf = sc.getServerSocketFactory();

            try {
                this.serverSocket = (SSLServerSocket) ssf.createServerSocket(port);
            } catch (java.net.BindException e) {
                if (onPortInUse != null)
                    onPortInUse.run();
                return;
            }

            System.out.println("[Server] Listening on port " + port);

            while (running) {
                try {
                    SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                    new Thread(() -> handleClient(clientSocket)).start();
                } catch (SocketException e) {
                    if (running)
                        e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Handles a client connection by processing commands from the input stream
     * and sending responses to the output stream.
     * 
     * Supported commands:
     * - DELETE: Remove a key from a table
     * - PUT: Store or update a key-value pair with signature verification
     * - SYNC: Send all data from all tables to the client
     * - SHARE: Receive and store secret shares for key reconstruction
     * - REQUEST_SHARES: Send stored shares to the requesting node
     * - SSESEARCH: Perform a search using SSE token and return results
     * 
     * @param socket the SSL socket for client communication
     */
    private void handleClient(SSLSocket socket) {
        try (
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))) {
            String line;
            while ((line = in.readLine()) != null) {
                String[] parts = line.split(" ");
                String cmd = parts[0].toLowerCase();
                System.out.println("[Server] Received command: " + cmd);

                switch (cmd) {

                    case "delete": {
                        if (parts.length >= 3) {
                            String tableName = parts[1];
                            String key = parts[2];
                            dataStore.delete(tableName, key);
                            System.out.println("[Server] Deleted key '" + key + "' from table '" + tableName + "'");
                        }
                        out.write("OK\n");
                        out.flush();
                        break;
                    }

                    case "put": {
                        if (parts.length < 8) {
                            System.out.println(
                                    "[Server] ERROR: Invalid PUT format. Expected 8 parts, got " + parts.length);
                            out.write("ERROR Invalid PUT format\n");
                            out.flush();
                            break;
                        }

                        String tableName = parts[1];
                        String key = parts[2];
                        String encodedValue = parts[3];
                        String value = new String(Base64.getDecoder().decode(encodedValue), StandardCharsets.UTF_8);
                        long ts = Long.parseLong(parts[4]);
                        String originId = parts[5];
                        String signature = parts[6];
                        String certBase64 = parts[7];

                        System.out.println("[Server] Received PUT for table: " + tableName + ", key: " + key
                                + ", value: " + value);

                        // Check if table exists
                        if (!dataStore.getTableNames().contains(tableName)) {
                            System.out.println("[Server] Table '" + tableName + "' does not exist - ignoring PUT");
                            out.write("ERROR Table does not exist\n");
                            out.flush();
                            break;
                        }

                        String data = key + ":" + value + ":" + ts;

                        try {
                            boolean valid = CryptoUtil.verify(data, signature, certBase64);
                            if (!valid) {
                                System.out.println("[SECURITY] Invalid signature from " + originId);
                                out.write("ERROR Invalid Signature\n");
                                out.flush();
                                break;
                            }
                        } catch (Exception e) {
                            System.err.println("[SECURITY] Verification failed: " + e.getMessage());
                            out.write("ERROR Verification failed\n");
                            out.flush();
                            break;
                        }

                        boolean putWasNew = dataStore.putWithTimestampAndOrigin(tableName, key, value, ts, originId,
                                certBase64, signature);

                        if (parentNode != null && putWasNew) {
                            parentNode.propagatePutToPeersExcept(tableName, key, value, ts, originId);
                        }
                        System.out.println("[Server] Sending OK response for PUT");
                        out.write("OK\n");
                        out.flush();
                        break;
                    }

                    // Update SYNC case to include table information
                    case "sync": {
                        Map<String, Map<String, DataStore.VersionedValue>> allTables = dataStore.getAllTables();
                        for (Map.Entry<String, Map<String, DataStore.VersionedValue>> tableEntry : allTables
                                .entrySet()) {
                            String tableName = tableEntry.getKey();
                            Map<String, DataStore.VersionedValue> tableData = tableEntry.getValue();

                            for (Map.Entry<String, DataStore.VersionedValue> entry : tableData.entrySet()) {
                                String key = entry.getKey();
                                DataStore.VersionedValue v = entry.getValue();
                                try {
                                    String plaintext = v.getDecryptedValue();
                                    String plaintextBase64 = java.util.Base64.getEncoder()
                                            .encodeToString(plaintext.getBytes("UTF-8"));
                                    // Format: tableName key plaintextBase64 timestamp originId
                                    // originSignatureBase64 originCertBase64
                                    out.write(tableName + " " + key + " " + plaintextBase64 + " " + v.timestamp + " " +
                                            v.originId + " " + v.originSignatureBase64 + " " + v.originCertBase64
                                            + "\n");
                                } catch (Exception e) {
                                    System.err.println("[Server][SYNC] Skipping key " + key + " in table " + tableName +
                                            " because decryption/signature failed: " + e.getMessage());
                                }
                            }
                        }
                        out.write("END\n");
                        out.flush();
                        break;
                    }

                    // Handler para receber shares
                    case "share": {
                        // Format: SHARE <targetNodeId> <senderNodeId> <keyType> <shareNumber>
                        // <shareData>
                        if (parts.length < 6) {
                            out.write("ERROR Invalid SHARE format\n");
                            out.flush();
                            break;
                        }

                        String targetNodeId = parts[1];
                        String senderNodeId = parts[2];
                        String keyType = parts[3];
                        int shareNumber = Integer.parseInt(parts[4]);
                        String shareData = parts[5];

                        // Check if the share is for this node
                        if (!targetNodeId.equals(parentNode.getNodeId())) {
                            out.write("ERROR Wrong target node\n");
                            out.flush();
                            break;
                        }

                        try {
                            SecretSharing.Share share = SecretSharing.Share.deserialize(shareData);

                            // Store in local HashMap (key = senderNodeId + "_" + keyType + "_" +
                            // shareNumber)
                            String mapKey = senderNodeId + "_" + keyType + "_" + shareNumber;

                            if ("AES".equals(keyType)) {
                                receivedSharesAES.put(mapKey, share);
                                System.out.println("[Server] Stored AES share from " + senderNodeId +
                                        " (share " + shareNumber + ") in local HashMap");
                            } else if ("HMAC".equals(keyType)) {
                                receivedSharesHMAC.put(mapKey, share);
                                System.out.println("[Server] Stored HMAC share from " + senderNodeId +
                                        " (share " + shareNumber + ") in local HashMap");
                            }

                            // Also store in CryptoUtil for reconstruction
                            CryptoUtil.storeReceivedShare(senderNodeId, keyType, shareNumber, shareData);

                            out.write("OK Share received and stored\n");
                            out.flush();

                        } catch (Exception e) {
                            System.err.println("[Server] Error processing share: " + e.getMessage());
                            out.write("ERROR Invalid share data\n");
                            out.flush();
                        }
                        break;
                    }

                    // Handler for share requests
                    case "request_shares": {
                        // Format: REQUEST_SHARES <requesterNodeId>
                        if (parts.length < 2) {
                            out.write("ERROR Invalid REQUEST_SHARES format\n");
                            out.flush();
                            break;
                        }

                        String requesterNodeId = parts[1];
                        System.out.println("[Server] Received share request from " + requesterNodeId);

                        // Send stored shares for this node
                        sendSharesToNode(requesterNodeId, out);

                        out.write("END\n");
                        out.flush();
                        break;
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Sends stored secret shares to a requesting node.
     * Sends both AES and HMAC shares stored for the requester.
     * 
     * @param requesterNodeId ID of the node requesting shares
     * @param out             BufferedWriter to send the shares to
     * @throws IOException if writing to the output stream fails
     */
    private void sendSharesToNode(String requesterNodeId, BufferedWriter out) throws IOException {
        int sentCount = 0;

        // Send AES shares
        for (Map.Entry<String, SecretSharing.Share> entry : receivedSharesAES.entrySet()) {
            String key = entry.getKey();
            SecretSharing.Share share = entry.getValue();

            // Extract information from the key: senderNodeId_keyType_shareNumber
            String[] parts = key.split("_");
            if (parts.length >= 3) {
                try {
                    String senderNodeId = parts[0];
                    String keyType = parts[1];
                    int shareNumber = Integer.parseInt(parts[2]);

                    // Check if this share belongs to the requester
                    // Since we don't have this information, we send all AES shares
                    if (senderNodeId.equals(requesterNodeId)) {
                        out.write("SHARE " + parentNode.getNodeId() + " " + requesterNodeId +
                                " " + keyType + " " + shareNumber + " " + share.serialize() + "\n");
                        System.out.println("[Server] Sending " + keyType + " share " + shareNumber +
                                " (from " + senderNodeId + ") to " + requesterNodeId);
                        sentCount++;
                    }

                } catch (NumberFormatException e) {
                    // Ignore malformed keys
                }
            }
        }

        // Send HMAC shares
        for (Map.Entry<String, SecretSharing.Share> entry : receivedSharesHMAC.entrySet()) {
            String key = entry.getKey();
            SecretSharing.Share share = entry.getValue();

            String[] parts = key.split("_");
            if (parts.length >= 3) {
                try {
                    String senderNodeId = parts[0];
                    String keyType = parts[1];
                    int shareNumber = Integer.parseInt(parts[2]);

                    out.write("SHARE " + parentNode.getNodeId() + " " + requesterNodeId +
                            " " + keyType + " " + shareNumber + " " + share.serialize() + "\n");
                    System.out.println("[Server] Sending " + keyType + " share " + shareNumber +
                            " (from " + senderNodeId + ") to " + requesterNodeId);
                    sentCount++;

                } catch (NumberFormatException e) {
                    // Ignore malformed keys
                }
            }
        }

        System.out.println("[Server] Sent " + sentCount + " shares to " + requesterNodeId);
    }

    /**
     * Gracefully shuts down the server by:
     * 1. Setting running flag to false
     * 2. Closing the server socket
     * 3. Joining the thread with timeout
     */
    public void shutdown() {
        running = false;
        try {
            if (serverSocket != null && !serverSocket.isClosed())
                serverSocket.close();
            this.join(1000);
            System.out.println("[Server] Server socket closed");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}