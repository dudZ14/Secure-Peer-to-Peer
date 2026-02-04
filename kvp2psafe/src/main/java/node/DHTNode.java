package node;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A Distributed Hash Table (DHT) node implementing a simplified Kademlia-like peer discovery mechanism.
 * 
 * <p>This class keeps a set of k-buckets, each storing peers grouped by XOR-distance (approximated here
 * using Java's hashCode modulo the DHT bit size). Each peer is represented by its ID, host, and port.
 * Nodes announce themselves, synchronize peers, and propagate JOIN events to maintain global connectivity.</p>
 *
 * <p>Key characteristics:</p>
 * <ul>
 *   <li>Uses 160-bit identifiers (similar to classic Kademlia).</li>
 *   <li>Each k-bucket can store up to K = 5 peers.</li>
 *   <li>Peer synchronization ensures full network convergence: every time a peer is added, we also import all peers known by it.</li>
 *   <li>A lightweight server listens on (port + 10000) to respond to JOIN and LISTPEERS messages.</li>
 * </ul>
 */
public class DHTNode {

    private final String nodeId;
    private final int port;
    
    /** Mapping bucketIndex -> list of peers */
    private final Map<Integer, CopyOnWriteArrayList<DhtPeer>> kBuckets = new ConcurrentHashMap<>();
    
    /** Maximum number of peers per bucket */
    private static final int K = 5;
    
    /** Number of bits in the DHT identifier space */
    private static final int BITS = 160;

    /**
     * Creates a DHT node with a given ID and base port.
     * 
     * @param nodeId unique identifier for this node
     * @param port base port where this peer's application runs
     */
    public DHTNode(String nodeId, int port) {
        this.nodeId = nodeId;
        this.port = port;
        initializeKBuckets();
    }

    /** Initializes all k-buckets (one per bit in the identifier space). */
    private void initializeKBuckets() {
        for (int i = 0; i < BITS; i++) {
            kBuckets.put(i, new CopyOnWriteArrayList<>());
        }
    }

    /**
     * Adds a peer to the appropriate k-bucket and synchronizes peer lists.
     *
     * @param id peer identifier
     * @param host peer IP/hostname
     * @param port peer application port
     */
    public synchronized void addPeer(String id, String host, int port) {
        if (id.equals(this.nodeId))
            return;

        int bucketIndex = getBucketIndex(id);
        CopyOnWriteArrayList<DhtPeer> bucket = kBuckets.get(bucketIndex);

        DhtPeer newPeer = new DhtPeer(id, host, port);
        if (!bucket.contains(newPeer)) {
        	
        	// Enforce a maximum size K for each k-bucket
            if (bucket.size() >= K)
                bucket.remove(0);
            
            bucket.add(newPeer);
            System.out.println("[DHT] Added peer " + id + " (bucket " + bucketIndex + ")");

         // After adding a peer, synchronize with its known peers// synchronize known peers with the new peer
            syncPeersFromPeer(newPeer);
        }
    }

    /**
     * Computes the bucket index for a peer using its hashCode modulo the DHT size.
     * 
     * @param peerId the ID of the peer
     * @return bucket index [0..BITS)
     */
    private int getBucketIndex(String peerId) {
        return Math.abs(peerId.hashCode()) % BITS;
    }

    /**
     * After adding a peer, this method queries that peer for its known peers,
     * ensuring global network convergence.
     *
     * <p>This works by sending a "LISTPEERS" command and importing all peers returned.</p>
     *
     * @param peer the peer to synchronize with
     */
    private void syncPeersFromPeer(DhtPeer peer) {
        try (Socket socket = new Socket(peer.host, peer.port + 10000);
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {

            out.println("LISTPEERS");
            String line;
            while ((line = in.readLine()) != null && !line.isEmpty()) {
                String[] parts = line.split(" ");
                if (parts.length == 3) {
                    String pid = parts[0];
                    String phost = parts[1];
                    int pport = Integer.parseInt(parts[2]);
                    if (!pid.equals(nodeId) && !peerExists(pid)) {
                        addPeer(pid, phost, pport);
                    }
                }
            }
        } catch (IOException ignored) {

        }
    }

    /** Announces this node to all known peers with a JOIN message. */
    public void announce() {
        for (DhtPeer peer : getAllPeers()) {
            sendJoin(peer.host, peer.port, nodeId, getLocalHost(), port);
        }
    }

    /**
     * Starts the DHT server thread, listening on port + 10000.
     * This server handles:
     * <ul>
     *   <li>JOIN messages</li>
     *   <li>LISTPEERS requests</li>
     * </ul>
     */
    public void startServer() {
        Thread serverThread = new Thread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(port + 10000)) {
                System.out.println("[DHT] Listening on " + (port + 10000));
                while (true) {
                    Socket socket = serverSocket.accept();
                    handleConnection(socket);
                }
            } catch (IOException e) {
                System.err.println("[DHT] Server stopped: " + e.getMessage());
            }
        }, "DHT-Server-" + nodeId);
        serverThread.setDaemon(true);
        serverThread.start();
    }

    /** Handles incoming JOIN or LISTPEERS messages from peers. */
    private void handleConnection(Socket socket) {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

            String msg = in.readLine();
            if (msg == null)
                return;

            if (msg.startsWith("JOIN")) {
                handleJoinMessage(msg);
            } else if (msg.equals("LISTPEERS")) {
                for (DhtPeer peer : getAllPeers()) {
                    out.println(peer.nodeId + " " + peer.host + " " + peer.port);
                }
                out.println();
            }

        } catch (IOException e) {
            System.err.println("[DHT] Connection error: " + e.getMessage());
        }
    }

    /**
     * Processes a JOIN message from a peer and updates the local DHT accordingly.
     * 
     * @param msg the JOIN message received
     */
    private void handleJoinMessage(String msg) {
        String[] parts = msg.split(" ");
        if (parts.length < 4)
            return;

        String joiningId = parts[1];
        String joiningHost = parts[2];
        int joiningPort = Integer.parseInt(parts[3]);

        String originId = parts.length >= 7 ? parts[4] : null;
        String originHost = parts.length >= 7 ? parts[5] : null;
        int originPort = parts.length >= 7 ? Integer.parseInt(parts[6]) : -1;

        if (joiningId.equals(nodeId))
            return;

        boolean isNewPeer = !peerExists(joiningId);
        addPeer(joiningId, joiningHost, joiningPort);

        // Add the origin peer (the one who introduced the joining peer)
        if (originId != null && !originId.equals(nodeId) && !peerExists(originId)) {
            addPeer(originId, originHost, originPort);
        }

        if (isNewPeer) {
            propagateNewPeer(joiningId, joiningHost, joiningPort);
            System.out.println("[DHT] New peer joined: " + joiningId + " -> propagated to all peers.");
        }
    }

    /** Propagates the newly joined peer to all known peers. */
    private void propagateNewPeer(String joiningId, String joiningHost, int joiningPort) {
        for (DhtPeer peer : getAllPeers()) {
            if (peer.nodeId.equals(joiningId) || peer.nodeId.equals(nodeId))
                continue;

            // Notify peer about joining node
            sendJoin(peer.host, peer.port, joiningId, joiningHost, joiningPort, nodeId, getLocalHost(), port);

            // Notify joining node about peer
            sendJoin(joiningHost, joiningPort, peer.nodeId, peer.host, peer.port, nodeId, getLocalHost(), port);
        }
    }

    /** Checks if a peer exists in any k-bucket. */
    private boolean peerExists(String peerId) {
        return getAllPeers().stream().anyMatch(p -> p.nodeId.equals(peerId));
    }

    /**
     * Sends a JOIN message with origin information (full propagation).
     */
    private void sendJoin(String host, int port,
            String joiningId, String joiningHost, int joiningPort,
            String originId, String originHost, int originPort) {
        try (Socket s = new Socket(host, port + 10000);
                PrintWriter out = new PrintWriter(s.getOutputStream(), true)) {
            out.println("JOIN " + joiningId + " " + joiningHost + " " + joiningPort +
                    " " + originId + " " + originHost + " " + originPort);
        } catch (IOException ignored) {
        }
    }

    /** Simpler sendJoin without explicit origin (origin = this node). */
    private void sendJoin(String host, int port, String joiningId, String joiningHost, int joiningPort) {
        sendJoin(host, port, joiningId, joiningHost, joiningPort, nodeId, getLocalHost(), port);
    }

    /** @return local machine's IP address (fallback to 127.0.0.1) */
    private String getLocalHost() {
        try {
            return InetAddress.getLocalHost().getHostAddress();
        } catch (Exception e) {
            return "127.0.0.1";
        }
    }

    /**
     * @return a flat list of all peers across all k-buckets
     */
    public List<DhtPeer> getAllPeers() {
        List<DhtPeer> allPeers = new ArrayList<>();
        for (CopyOnWriteArrayList<DhtPeer> bucket : kBuckets.values()) {
            allPeers.addAll(bucket);
        }
        return allPeers;
    }

    /** Represents a peer in the DHT. */
    public static class DhtPeer {
        final String nodeId;
        final String host;
        final int port;

        DhtPeer(String nodeId, String host, int port) {
            this.nodeId = nodeId;
            this.host = host;
            this.port = port;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof DhtPeer && nodeId.equals(((DhtPeer) o).nodeId);
        }

        @Override
        public int hashCode() {
            return nodeId.hashCode();
        }

        @Override
        public String toString() {
            return nodeId + "@" + host + ":" + port;
        }
    }
}
