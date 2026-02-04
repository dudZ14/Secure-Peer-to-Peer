# DHT P2P Secure Network
## Author: dudZ14

## Description
Implements a DHT (Distributed Hash Table) in Java. Each node can store data, discover peers on the network, and send PUT commands to remote nodes. It is also possible to obtain values using GET, with these commands being transmitted via TLS and with signatures. Values are also stored in encrypted form and with HMAC. Searchable Symmetric Encryption (SSE, Cash) and Shamir Secret Sharing are also implemented. To ensure availability, when the node disconnects and returns to the network, it recovers its state. In addition, write conflicts are resolved with timestamps (the most recent PUT is the one that remains).

## How to execute
- Open the terminal, go to the “kvp2psafe” directory, and run the application using the command “mvn javafx:run” with Maven installed.
- When you have finished running the script, you can delete the keystores and trust stores generated using the “clean.bat” script.

## Structure
- **GUI**: Graphic Interface using JavaFx
- **DataStore**: PUT and GET operations
- **P2PClient e P2PServer**: Classes that represent the peer, which is both client and server, and communicates with others securely using PUT and GET commands.
- **DHTNode**: Manages the routing table (bucket) and DHT communication.
- **P2PNode**: Represents the complete node (client, server, DHT, DataStore).
- **CryptoUtil**: Represents the class with auxiliary methods related to security.
- **SecretSharing**: Class that implements Shamir's Secret Sharing scheme.
- **CashSSE**: Class that implements a simplified Searchable Symmetric Encryption (SSE) scheme.
