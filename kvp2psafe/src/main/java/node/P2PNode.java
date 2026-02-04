package node;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import node.CashSSE.Client;
import node.CashSSE.Server;

/**
 * P2PNode represents a node in a peer-to-peer network with searchable symmetric
 * encryption (SSE)
 * and distributed hash table (DHT) capabilities.
 * 
 * This node provides:
 * 1. P2P communication through SSL/TLS connections
 * 2. Distributed data storage with versioning and synchronization
 * 3. Searchable symmetric encryption for secure keyword search
 * 4. Automatic key sharing and reconstruction using secret sharing
 * 5. Node discovery and online status tracking
 * 
 * The node maintains connections to known peers and can bootstrap itself
 * into the network by synchronizing data with existing peers.
 * 
 * @see P2PServer
 * @see DHTNode
 * @see DataStore
 * @see CryptoUtil
 * @see SecretSharing
 */
public class P2PNode {

    private final String nodeId; // Unique identifier for this node
    private final int port; // Port number on which this node listens
    private final DataStore dataStore; // Data store for key-value pairs with versioning
    private final P2PServer server; // Server component for handling incoming P2P connections
    private final DHTNode dht; // Distributed Hash Table component for peer discovery
    private final ScheduledExecutorService printScheduler; // Scheduler for periodic tasks like monitoring online nodes
    private static final String ONLINE_NODES_TABLE = "_system_online_nodes"; // System table name for tracking online
                                                                             // nodes

    private final Client sseClient; // Client component for searchable symmetric encryption operations
    private final Server sseServer; // Server component for searchable symmetric encryption operations

    /**
     * Inner class representing a blind node address (peer known without prior
     * contact).
     * Contains the peer's ID, host, and port for connection.
     */
    public class BlindNodeAddress {

        String peerId; // Peer's unique identifier
        String host; // Hostname or IP address of the peer
        int peerPort; // Port number of the peer

        /**
         * Constructs a BlindNodeAddress with the specified details.
         * 
         * @param peerId   unique identifier of the peer
         * @param host     hostname or IP address of the peer
         * @param peerPort port number of the peer
         */
        public BlindNodeAddress(String peerId, String host, int peerPort) {
            this.peerId = peerId;
            this.host = host;
            this.peerPort = peerPort;
        }

        /**
         * Returns the peer's unique identifier.
         * 
         * @return the peer ID
         */
        public String getPeerId() {
            return peerId;
        }

        /**
         * Returns the hostname or IP address of the peer.
         * 
         * @return the host
         */
        public String getHost() {
            return host;
        }

        /**
         * Returns the port number of the peer.
         * 
         * @return the peer port
         */
        public int getPeerPort() {
            return peerPort;
        }

        /**
         * Returns a string representation of the blind node address.
         * 
         * @return string in format "peerId (host:port)"
         */
        @Override
        public String toString() {
            return peerId + " (" + host + ":" + peerPort + ")";
        }
    }

    /** List of known peers for blind bootstrapping */
    List<BlindNodeAddress> knownPeers = List.of(
            new BlindNodeAddress("node1", "127.0.0.1", 5000),
            new BlindNodeAddress("node2", "127.0.0.1", 5001),
            new BlindNodeAddress("node3", "127.0.0.1", 5002));

    /**
     * Constructs a new P2PNode with the specified node ID and port.
     * Initializes all components including data store, server, DHT, and SSE.
     * 
     * @param nodeId unique identifier for this node
     * @param port   port number on which this node will listen
     * @throws RuntimeException if crypto initialization fails
     */
    public P2PNode(String nodeId, int port) {
        this.nodeId = nodeId;
        this.port = port;
        this.dataStore = new DataStore();
        this.server = new P2PServer(port, dataStore, this);
        this.dht = new DHTNode(nodeId, port);
        this.printScheduler = Executors.newScheduledThreadPool(1);

        this.sseServer = new Server();
        this.sseClient = new Client(sseServer);

        // Create system table for online nodes
        this.dataStore.createTable(ONLINE_NODES_TABLE);

        // Create system table for online nodes
        this.dataStore.setP2PNode(this);
        this.dataStore.setSSEClient(sseClient); // Pass client for indexing
        CryptoUtil.setP2PNode(this);

        try {
            CryptoUtil.init(nodeId);
        } catch (Exception e) {
            throw new RuntimeException("Failed to init crypto for node " + nodeId, e);
        }
    }

    /**
     * Returns the SSE server component for searchable symmetric encryption.
     * 
     * @return the SSE server instance
     */
    public Server getSSEServer() {
        return sseServer;
    }

    /**
     * Performs a global search across all tables and peers for the given keyword.
     * Searches both local SSE index
     * 
     * @param keyword the keyword to search for
     * @return map of peer IDs to lists of search results (format: tableName:key)
     * @throws Exception
     */
    public Map<String, List<String>> localSearch(String keyword) throws Exception {
        Map<String, List<String>> allResults = new HashMap<>();

        // 1. Search local index first
        try {
            List<String> localResults = sseClient.search(keyword); // agora search recebe keyword
            if (!localResults.isEmpty()) {
                allResults.put(this.nodeId + " (Local)", localResults);
            }
        } catch (Exception e) {
            System.err.println("[P2PNode] Error searching local SSE index: " + e.getMessage());
        }

        return allResults;
    }

    /**
     * Starts the P2P node by:
     * 1. Starting the P2P server
     * 2. Starting the DHT server
     * 3. Registering this node as online
     * 4. Starting the online nodes monitor
     */
    public void start() {
        server.start();
        dht.startServer();

        // Register this node as online
        registerAsOnline();

        // Start monitoring (just for printing)
        startOnlineNodesMonitor();
    }

    /**
     * Registers this node as online in the system table and propagates
     * the status to all known peers.
     */
    private void registerAsOnline() {
        String portStr = String.valueOf(port);
        long ts = System.currentTimeMillis();
        dataStore.putWithTimestamp(ONLINE_NODES_TABLE, nodeId, portStr, ts, nodeId);

        // Propagate to all known peers
        List<DHTNode.DhtPeer> peers = dht.getAllPeers();
        if (!peers.isEmpty()) {
            propagatePutToPeers(ONLINE_NODES_TABLE, nodeId, portStr, ts);
            System.out.println("[Node] Registered as ONLINE and propagated to " + peers.size() + " peers");
        } else {
            System.out.println("[Node] Registered as ONLINE: " + nodeId + " -> " + port);
        }
    }

    /**
     * Unregisters this node as online from the system table and propagates
     * the removal to all known peers.
     * 
     * @return true if unregistration was successful
     */
    private boolean unregisterAsOnline() {
        // Remove from local store
        dataStore.delete(ONLINE_NODES_TABLE, nodeId);

        // Propagate removal to all known peers
        System.out.println("[Node] Unregistered as OFFLINE");
        return propagateDelete(ONLINE_NODES_TABLE, nodeId);
    }

    /**
     * Unregisters this node as online from the system table and propagates
     * the removal to all known peers.
     * 
     * @return true if unregistration was successful
     */
    private void startOnlineNodesMonitor() {
        // Just print every 6 seconds for testing
        printScheduler.scheduleAtFixedRate(() -> {
            try {
                printOnlineNodes();
            } catch (Exception e) {
                System.err.println("[Monitor] Error: " + e.getMessage());
            }
        }, 6, 6, TimeUnit.SECONDS);
    }

    /**
     * Prints a formatted list of all online nodes to the console.
     */
    public void printOnlineNodes() {
        System.out.println("\n========================================");
        System.out.println("    ONLINE NODES MAP [" + nodeId + "]");
        System.out.println("========================================");

        Map<String, DataStore.VersionedValue> onlineNodes = dataStore.getAll(ONLINE_NODES_TABLE);

        if (onlineNodes.isEmpty()) {
            System.out.println("  [No nodes registered]");
        } else {
            for (Map.Entry<String, DataStore.VersionedValue> entry : onlineNodes.entrySet()) {
                String nid = entry.getKey();
                String portValue;
                try {
                    portValue = entry.getValue().getDecryptedValue();
                } catch (Exception e) {
                    portValue = "ERROR";
                }

                String self = nid.equals(nodeId) ? " (ME)" : "";
                System.out.printf("  %-15s -> Port %-6s%s%n", nid, portValue, self);
            }

            System.out.println("----------------------------------------");
            System.out.printf("  Total: %d nodes%n", onlineNodes.size());
        }

        System.out.println("========================================\n");
    }

    /**
     * Returns a map of all online nodes with their port numbers.
     * 
     * @return map of node IDs to port numbers
     */
    public Map<String, Integer> getOnlineNodes() {
        Map<String, Integer> result = new HashMap<>();
        Map<String, DataStore.VersionedValue> onlineNodes = dataStore.getAll(ONLINE_NODES_TABLE);

        for (Map.Entry<String, DataStore.VersionedValue> entry : onlineNodes.entrySet()) {
            String nid = entry.getKey();
            try {
                String portStr = entry.getValue().getDecryptedValue();
                result.put(nid, Integer.parseInt(portStr));
            } catch (Exception e) {
                System.err.println("[Node] Error parsing port for " + nid);
            }
        }

        return result;
    }

    /**
     * Callback method invoked by DataStore when the online nodes table is updated.
     * Triggers key share distribution and reconstruction among online nodes.
     */
    public void onOnlineNodesUpdated() {
        Map<String, Integer> onlineNodes = getOnlineNodes();

        // Remove self from the list
        onlineNodes.remove(nodeId);
        System.out.println("[ShareDistribution] " + (onlineNodes.size() + 1) +
                " nodes online - generating and distributing all shares...");

        System.out.println("DEBUG: Chegou antes de areKeysReconstructed()");
        if (CryptoUtil.areKeysReconstructed()) {
            System.out.println("[ShareDistribution] Keys are already done. Aborting share distribution.");
            return;
        }

        System.out.println("DEBUG: Chegou antes de distributeShares()");
        // Generate and distribute shares to online nodes
        distributeSharesToOnlineNodes(onlineNodes);

        // System.out.println("DEBUG: Chegou antes de requestShares()");
        // Request shares from other nodes to reconstruct the ke
        // requestSharesFromOnlineNodes();

    }

    /**
     * Returns a reference to this P2PNode instance for use by CryptoUtil.
     * 
     * @return this P2PNode instance
     */
    public P2PNode getP2PNodeInstance() {
        return this;
    }

    // Atualização no método bootstrap() do P2PNode.java
    // Remove a espera explícita pelas chaves, pois agora são reconstruídas
    // on-demand

    /**
     * Bootstraps this node by connecting to a specific peer and synchronizing data.
     * Establishes a secure TLS connection and performs bidirectional data sync.
     * 
     * @param peerId   ID of the peer to bootstrap from
     * @param host     hostname or IP address of the peer
     * @param peerPort port number of the peer
     */
    public void bootstrap(String peerId, String host, int peerPort) {
        if (peerId.equals(nodeId)) {
            System.out.println("[Node] Skipping bootstrap to self");
            return;
        }

        dht.addPeer(peerId, host, peerPort);
        dht.announce();

        System.err.println("BOOTSTRAPPING .....................................");

        new Thread(() -> {
            try {
                System.out.println(
                        "[Node] Starting secure bootstrap with peer " + peerId + " (" + host + ":" + peerPort + ")");
                P2PClient client = new P2PClient(host, peerPort);

                Map<String, Map<String, Map<String, String>>> allPeerData = client.fetchAllData();

                // Sync online nodes table FIRST
                Map<String, Map<String, String>> peerOnlineNodes = allPeerData.getOrDefault(ONLINE_NODES_TABLE,
                        new HashMap<>());
                System.out.println("[Bootstrap] Received " + peerOnlineNodes.size() + " online nodes from peer");
                if (!peerOnlineNodes.isEmpty()) {
                    syncOnlineNodesTable(peerOnlineNodes);
                }

                // Now send our online status to the peer
                sendOnlineStatusToPeer(client);

                System.out.println("DEBUG: Chegou ANTES de registerAsOnline()");
                // After registering as online
                registerAsOnline();
                System.out.println("DEBUG: Chegou DEPOIS de registerAsOnline()");

                // Get online nodes
                Map<String, Integer> onlineNodes = getOnlineNodes();

                // Remove self from the list
                System.out.println("TAMANHO DAS ONLINE NODES: " + onlineNodes.size());

                // Check if we have at least 3 nodes online (threshold 2 + 1)
                if (onlineNodes.size() >= 2) {

                    // Sync global table for backward compatibility
                    Map<String, Map<String, String>> peerData = allPeerData.getOrDefault("global", new HashMap<>());

                    // REMOVED: Explicit key waiting logic
                    // Keys will be reconstructed on-demand when encrypt/decrypt is called
                    System.out.println("[Bootstrap] Starting data sync (keys will be reconstructed on-demand)...");

                    // Synchronize global table
                    if (dataStore.getAll("global").isEmpty() && !peerData.isEmpty()) {
                        recoverFromPeer(peerId, peerData);
                    } else if (!dataStore.getAll("global").isEmpty() && peerData.isEmpty()) {
                        syncToEmptyPeer(peerId, client);
                    } else if (!dataStore.getAll("global").isEmpty() && !peerData.isEmpty()) {
                        reconcileWithPeer(peerId, client, peerData);
                    } else {
                        System.out.println("[Node] Both local and peer databases are empty – nothing to sync.");
                    }

                } else {
                    System.out.println("[Node] Not enough nodes online (" +
                            (onlineNodes.size()) + "). Need at least 3.");
                }

            } catch (Exception e) {
                System.err.println("[Node] Bootstrap sync failed with peer " + peerId + ": " + e.getMessage());
                e.printStackTrace();
            }
        }).start();
    }

    /**
     * Distributes secret shares to all online nodes for key reconstruction.
     * 
     * @param onlineNodes map of node IDs to port numbers for distribution targets
     */
    private void distributeSharesToOnlineNodes(Map<String, Integer> onlineNodes) {
        try {
            // Generate AES and HMAC shares
            SecretSharing.Share[] aesShares = CryptoUtil.generateAndSplitAesKey();
            SecretSharing.Share[] hmacShares = CryptoUtil.generateAndSplitHmacKey();

            System.out.println("[ShareDistribution] Generated " + aesShares.length + " AES shares");
            System.out.println("[ShareDistribution] Generated " + hmacShares.length + " HMAC shares");

            // Distribute all shares to online nodes
            int shareIndex = 1;
            for (Map.Entry<String, Integer> entry : onlineNodes.entrySet()) {
                if (shareIndex >= aesShares.length) {
                    break;
                }

                String targetNodeId = entry.getKey();
                int targetPort = entry.getValue();
                System.out.println("[ShareDistribution] Sending shares to node " + targetNodeId +
                        " at port " + targetPort);

                try {
                    // Send AES share
                    sendShareToNode(targetNodeId, "localhost", targetPort,
                            aesShares[shareIndex], "AES", shareIndex + 1);

                    // Send HMAC share
                    sendShareToNode(targetNodeId, "localhost", targetPort,
                            hmacShares[shareIndex], "HMAC", shareIndex + 1);

                    System.out.println("[ShareDistribution] Sent share " + (shareIndex + 1) +
                            " to node " + targetNodeId);
                    shareIndex++;

                } catch (Exception e) {
                    System.err.println("[ShareDistribution] Failed to send share to " +
                            targetNodeId + ": " + e.getMessage());
                }
            }

            System.out.println("[ShareDistribution] All shares distributed to " + shareIndex + " nodes");

        } catch (Exception e) {
            System.err.println("[ShareDistribution] Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Requests secret shares from all online nodes for key reconstruction.
     */
    public void requestSharesFromOnlineNodes() {
        try {
            Map<String, Integer> onlineNodes = getOnlineNodes();
            onlineNodes.remove(nodeId);

            if (!onlineNodes.isEmpty()) {
                System.out.println("[ShareRecovery] Requesting shares from " + onlineNodes.size() + " online nodes");

                for (Map.Entry<String, Integer> entry : onlineNodes.entrySet()) {
                    String targetNodeId = entry.getKey();
                    int targetPort = entry.getValue();

                    try {
                        P2PClient client = new P2PClient("localhost", targetPort);
                        String response = client.sendCommand("REQUEST_SHARES " + nodeId);

                        // Process received shares from response
                        processReceivedShares(response);

                        System.out.println("[ShareRecovery] Received shares from node " + targetNodeId);
                    } catch (Exception e) {
                        System.err.println("[ShareRecovery] Failed to request shares from " +
                                targetNodeId + ": " + e.getMessage());
                    }
                }

                // Reconstruct AES key after receiving shares
                reconstructKeysFromReceivedShares();
            }
        } catch (Exception e) {
            System.err.println("[ShareRecovery] Error requesting shares: " + e.getMessage());
        }
    }

    /**
     * Processes shares received from other nodes in response to share requests.
     * 
     * @param response the response string containing share data
     */
    private void processReceivedShares(String response) {
        String[] lines = response.split("\n");
        for (String line : lines) {

            if (line.startsWith("SHARE")) {
                String[] parts = line.split(" ");

                if (parts.length >= 6) {
                    // Formato: SHARE <senderNodeId> <targetNodeId> <keyType> <shareNumber>
                    // <shareData>
                    String senderNodeId = parts[1]; // Who sent the share
                    String targetNodeId = parts[2]; // Who it's destined for
                    String keyType = parts[3]; // "AES" or "HMAC"
                    int shareNumber = Integer.parseInt(parts[4]); // Share number
                    String shareData = parts[5]; // Share data

                    // Check if the share is for this node
                    if (targetNodeId.equals(nodeId)) {
                        // Store in CryptoUtil
                        CryptoUtil.storeReceivedShare(senderNodeId, keyType, shareNumber, shareData);
                        System.out.println("[ShareRecovery] Stored " + keyType + " share " + shareNumber +
                                " from " + senderNodeId);
                    }
                }
            }
        }
    }

    /**
     * Reconstructs AES and HMAC keys from received shares.
     */
    private void reconstructKeysFromReceivedShares() {
        try {
            // Reconstruct AES key
            if (CryptoUtil.reconstructAesKeyFromShares()) {
                System.out.println("[Node] AES key successfully reconstructed");
            }

            // Reconstruct HMAC key
            if (CryptoUtil.reconstructHmacKeyFromShares()) {
                System.out.println("[Node] HMAC key successfully reconstructed");
            }
        } catch (Exception e) {
            System.err.println("[Node] Error reconstructing keys: " + e.getMessage());
        }
    }

    /**
     * Sends a secret share to a specific node.
     * 
     * @param targetNodeId ID of the node to receive the share
     * @param host         hostname or IP address of the target node
     * @param port         port number of the target node
     * @param share        the share to send
     * @param keyType      type of key ("AES" or "HMAC")
     * @param shareNumber  the share number/index
     * @throws Exception if sending fails
     */
    private void sendShareToNode(String targetNodeId, String host, int port,
            SecretSharing.Share share, String keyType, int shareNumber) throws Exception {
        P2PClient client = new P2PClient(host, port);

        // Prepare share data
        String shareData = share.serialize();
        String command = "SHARE " + targetNodeId + " " + nodeId + " " + keyType +
                " " + shareNumber + " " + shareData;

        client.sendCommand(command);
    }

    /**
     * Sends this node's online status to a specific peer.
     * 
     * @param client P2PClient connected to the peer
     */
    private void sendOnlineStatusToPeer(P2PClient client) {
        try {
            String portStr = String.valueOf(port);
            long ts = System.currentTimeMillis();
            String data = nodeId + ":" + portStr + ":" + ts;
            String signature = CryptoUtil.sign(data);
            String certBase64 = CryptoUtil.getCertificateBase64();

            String command = "PUT " + ONLINE_NODES_TABLE + " " + nodeId + " " + portStr + " " + ts + " " +
                    nodeId + " " + signature + " " + certBase64;
            client.sendCommand(command);
            System.out.println("[Bootstrap] Sent our online status to peer");
        } catch (Exception e) {
            System.err.println("[Bootstrap] Failed to send online status: " + e.getMessage());
        }
    }

    /**
     * Synchronizes the online nodes table from peer data.
     * 
     * @param peerOnlineNodes map of online nodes received from peer
     */
    private void syncOnlineNodesTable(Map<String, Map<String, String>> peerOnlineNodes) {
        System.out.println("[Sync] Processing " + peerOnlineNodes.size() + " online nodes from peer");
        for (Map.Entry<String, Map<String, String>> entry : peerOnlineNodes.entrySet()) {
            String nid = entry.getKey();
            Map<String, String> info = entry.getValue();

            try {
                String portStr = info.get("value");
                long ts = Long.parseLong(info.get("timestamp"));
                String originId = info.get("originId");
                String originSig = info.get("originSignatureBase64");
                String originCert = info.get("originCertBase64");

                String signedData = nid + ":" + portStr + ":" + ts;

                if (!CryptoUtil.verify(signedData, originSig, originCert)) {
                    System.err.println("[Bootstrap] Invalid signature for online node " + nid);
                    continue;
                }

                dataStore.putWithTimestampAndOrigin(ONLINE_NODES_TABLE, nid, portStr, ts, originId, originCert,
                        originSig);
                System.out.println("[Sync] ✓ Added online node: " + nid + " -> port " + portStr);
            } catch (Exception e) {
                System.err.println("[Bootstrap] Failed to sync online node " + nid + ": " + e.getMessage());
            }
        }
    }

    /**
     * Recovers data from a peer when local database is empty.
     * 
     * @param peerId   ID of the peer to recover from
     * @param peerData map of data received from peer
     */
    private void recoverFromPeer(String peerId, Map<String, Map<String, String>> peerData) {
        System.out.println("[Bootstrap] Recovering database from peer " + peerId);

        for (Map.Entry<String, Map<String, String>> entry : peerData.entrySet()) {
            String key = entry.getKey();
            Map<String, String> info = entry.getValue();

            try {
                String plaintext = info.get("value");
                long ts = Long.parseLong(info.get("timestamp"));
                String originId = info.get("originId");
                String originSig = info.get("originSignatureBase64");
                String originCert = info.get("originCertBase64");

                String signedData = key + ":" + plaintext + ":" + ts;

                if (!CryptoUtil.verify(signedData, originSig, originCert)) {
                    System.err.println("[Bootstrap] Invalid signature for key " + key + " from " + originId);
                    continue;
                }

                dataStore.putWithTimestampAndOrigin("global", key, plaintext, ts, originId, originCert, originSig);
            } catch (Exception e) {
                System.err.println("[Bootstrap] Failed to import key " + entry.getKey() + ": " + e.getMessage());
            }
        }

        System.out.println("[Node] Database recovered from peer " + peerId + " via secure TLS connection");
    }

    /**
     * Synchronizes local database to an empty peer.
     * 
     * @param peerId ID of the peer to sync to
     * @param client P2PClient connected to the peer
     */
    private void syncToEmptyPeer(String peerId, P2PClient client) {
        System.out.println("[Bootstrap] Syncing full local DB to empty peer " + peerId);

        for (Map.Entry<String, DataStore.VersionedValue> entry : dataStore.getAll("global").entrySet()) {
            String key = entry.getKey();
            DataStore.VersionedValue localVal = entry.getValue();

            try {
                String plaintext = localVal.getDecryptedValue();
                String data = key + ":" + plaintext + ":" + localVal.timestamp;

                String signature = CryptoUtil.sign(data);
                String certBase64 = CryptoUtil.getCertificateBase64();

                String command = "PUT global " + key + " " + plaintext + " " + localVal.timestamp + " " +
                        nodeId + " " + signature + " " + certBase64;
                client.sendCommand(command);

            } catch (Exception e) {
                System.err.println(
                        "[Security] Failed to send PUT for key " + key + " to peer " + peerId + ": " + e.getMessage());
            }
        }

        System.out.println("[Node] Peer " + peerId + " synchronized from local database via secure TLS connection");
    }

    /**
     * Reconciles data bidirectionally with a peer when both have data.
     * 
     * @param peerId   ID of the peer to reconcile with
     * @param client   P2PClient connected to the peer
     * @param peerData map of data received from peer
     */
    private void reconcileWithPeer(String peerId, P2PClient client, Map<String, Map<String, String>> peerData) {
        System.out.println("[Bootstrap] Reconciling data with peer " + peerId);

        for (Map.Entry<String, Map<String, String>> entry : peerData.entrySet()) {
            String key = entry.getKey();
            Map<String, String> info = entry.getValue();

            try {
                String plaintext = info.get("value");
                long ts = Long.parseLong(info.get("timestamp"));
                String originId = info.get("originId");
                String originSig = info.get("originSignatureBase64");
                String originCert = info.get("originCertBase64");

                String signedData = key + ":" + plaintext + ":" + ts;

                if (!CryptoUtil.verify(signedData, originSig, originCert)) {
                    System.err.println("[Sync] Invalid signature for key " + key + " from " + originId);
                    continue;
                }

                long localTs = dataStore.getTimestamp("global", key);
                if (localTs == -1 || ts > localTs) {
                    dataStore.putWithTimestampAndOrigin("global", key, plaintext, ts, originId, originCert, originSig);
                    System.out.println("[Sync] Updated key '" + key + "' from peer " + peerId);
                }
            } catch (Exception e) {
                System.err.println("[Sync] Failed to reconcile key " + entry.getKey() + ": " + e.getMessage());
            }
        }

        for (Map.Entry<String, DataStore.VersionedValue> entry : dataStore.getAll("global").entrySet()) {
            String key = entry.getKey();
            DataStore.VersionedValue localVal = entry.getValue();
            Map<String, String> peerInfo = peerData.get(key);

            boolean shouldSend = (peerInfo == null)
                    || (localVal.timestamp > Long.parseLong(peerInfo.get("timestamp")));

            if (shouldSend) {
                try {
                    String plaintext = localVal.getDecryptedValue();
                    String data = key + ":" + plaintext + ":" + localVal.timestamp;

                    String signature = CryptoUtil.sign(data);
                    String certBase64 = CryptoUtil.getCertificateBase64();

                    String command = "PUT global " + key + " " + plaintext + " " + localVal.timestamp + " "
                            + nodeId + " " + signature + " " + certBase64;
                    client.sendCommand(command);

                    System.out.println("[Sync] Sent newer key '" + key + "' to peer " + peerId);
                } catch (Exception e) {
                    System.err.println("[Sync] Failed to send updated key " + key + " to peer: " + e.getMessage());
                }
            }
        }

        System.out.println("[Node] Full bi-directional reconciliation completed with peer " + peerId);
    }

    /**
     * Propagates a PUT operation to all peers.
     * 
     * @param tableName     name of the table
     * @param key           key to put
     * @param value         value to put
     * @param ts            timestamp
     * @param originId      ID of the originating node
     * @param excludeOrigin whether to exclude the origin node from propagation
     */
    private void propagatePut(String tableName, String key, String value, long ts, String originId,
            boolean excludeOrigin) {
        List<DHTNode.DhtPeer> peers = dht.getAllPeers();

        try {
            String data = key + ":" + value + ":" + ts;
            String signature = CryptoUtil.sign(data);
            String certBase64 = CryptoUtil.getCertificateBase64();

            String encodedValue = Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));

            String command = "PUT " + tableName + " " + key + " " + encodedValue + " " + ts + " " + originId + " " + signature
                    + " " + certBase64;

            for (DHTNode.DhtPeer peer : peers) {
                if (excludeOrigin && peer.nodeId.equals(originId))
                    continue;

                new Thread(() -> {
                    try {
                        P2PClient client = new P2PClient(peer.host, peer.port);
                        client.sendCommand(command);
                    } catch (Exception e) {
                        // Silent fail for propagation
                        System.out.println("[Node] Failed to propagate PUT to " + peer.nodeId + ": " + e.getMessage());
                    }
                }).start();
            }
        } catch (Exception e) {
            System.err.println("[Security] Failed to sign message: " + e.getMessage());
        }
    }

    /**
     * Propagates a DELETE operation to all online nodes.
     * (Currently the DELETE operation is not used)
     * 
     * @param tableName name of the table
     * @param key       key to delete
     * @return true if propagation was attempted
     */
    private boolean propagateDelete(String tableName, String key) {
        boolean retorno = false;
        String command = "DELETE " + tableName + " " + key;

        Map<String, DataStore.VersionedValue> onlineNodes = dataStore.getAll(ONLINE_NODES_TABLE);

        if (onlineNodes.isEmpty()) {
            System.out.println("  [No nodes registered]");
        } else {
            for (Map.Entry<String, DataStore.VersionedValue> entry : onlineNodes.entrySet()) {
                System.out.println("[Node] Propagating DELETE to online node: " + entry.getKey());
                String nid = entry.getKey();
                if (nid.equals(nodeId)) {
                    continue; // Skip self
                }

                try {
                    String portValue = entry.getValue().getDecryptedValue();
                    P2PClient client = new P2PClient("localhost", Integer.parseInt(portValue));
                    client.sendCommand(command);
                } catch (Exception e) {
                    // Silent fail for propagation
                    System.out.println("[Node] Failed to propagate DELETE to " + nid + ": " + e.getMessage());
                }

            }
        }
        retorno = true;
        return retorno;
    }

    /**
     * Performs blind bootstrap by attempting to connect to all known peers
     * from the predefined list.
     */
    public void BlindBootstrap() {
        for (BlindNodeAddress peer : knownPeers) {

            // skip own node
            if (peer.getPeerId().equals(nodeId)) {
                System.out.println("[Node] Skipping bootstrap to self: " + peer);
                continue;
            }

            System.out.println("[Node] Attempting blind bootstrap to " + peer);
            bootstrap(peer.getPeerId(), peer.getHost(), peer.getPeerPort());
        }
    }

    /**
     * Propagates a PUT operation to all peers.
     * 
     * @param tableName name of the table
     * @param key       key to put
     * @param value     value to put
     * @param ts        timestamp
     */
    private void propagatePutToPeers(String tableName, String key, String value, long ts) {
        propagatePut(tableName, key, value, ts, nodeId, false);
    }

    /**
     * Propagates a PUT operation to all peers.
     * 
     * @param tableName name of the table
     * @param key       key to put
     * @param value     value to put
     * @param ts        timestamp
     */
    public void propagatePutToPeersExcept(String tableName, String key, String value, long ts, String originId) {
        propagatePut(tableName, key, value, ts, originId, true);
    }

    /**
     * Performs a global PUT operation that stores locally and propagates to all
     * peers.
     * 
     * @param tableName name of the table
     * @param key       key to put
     * @param value     value to put
     */
    public void globalPut(String tableName, String key, String value) {
        long ts = System.currentTimeMillis();
        dataStore.putWithTimestamp(tableName, key, value, ts, nodeId);
        propagatePutToPeers(tableName, key, value, ts);
    }

    /**
     * Creates a new table in the data store.
     * 
     * @param tableName name of the table to create
     * @return true if the table was created successfully
     */
    public boolean createTable(String tableName) {
        return dataStore.createTable(tableName);
    }

    /**
     * Performs a global GET operation from the specified table.
     * 
     * @param tableName name of the table
     * @param key       key to retrieve
     * @return the value associated with the key, or null if not found
     */
    public String globalGet(String tableName, String key) {
        return dataStore.get(tableName, key);
    }

    /**
     * Returns the data store instance.
     * 
     * @return the DataStore instance
     */
    public DataStore getDataStore() {
        return dataStore;
    }

    /**
     * Returns the P2P server instance.
     * 
     * @return the P2PServer instance
     */
    public P2PServer getServer() {
        return server;
    }

    /**
     * Returns the DHT node instance.
     * 
     * @return the DHTNode instance
     */
    public DHTNode getDHT() {
        return dht;
    }

    /**
     * Returns the port number this node listens on.
     * 
     * @return the port number
     */
    public int getPort() {
        return port;
    }

    /**
     * Returns the unique identifier of this node.
     * 
     * @return the node ID
     */
    public String getNodeId() {
        return nodeId;
    }

    /**
     * Gracefully shuts down the node by:
     * 1. Unregistering as online
     * 2. Stopping the scheduler
     * 3. Shutting down the P2P server
     */
    public void shutdown() {
        System.out.println("[Node] Shutting down " + nodeId);

        // Unregister as online before shutdown
        if (unregisterAsOnline()) {
            // Stop scheduler
            printScheduler.shutdown();
            try {
                if (!printScheduler.awaitTermination(2, TimeUnit.SECONDS)) {
                    printScheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                printScheduler.shutdownNow();
            }

            server.shutdown();
            System.out.println("[Node] Shutdown complete.");
        }
    }
}
