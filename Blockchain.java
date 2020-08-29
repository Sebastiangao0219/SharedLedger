
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.*;

public class Blockchain {
    static int processID; // define a process ID to store the first argument, 0, 1, or 2
    static int processNumber = 3;  // define the total process number, in this program, we have 3.
    static String serverName = "localhost";  // define a server name and assigned it a value
    static PrivateKey privateKey; // define a PrivateKey
    static int blockNumber = 1; // a block number, which will insert to blockRecord once it got verified, and will do blockNumber++ in BlockchainServer after it adds to blockchain for future use.
    static LinkedBlockingDeque<BlockRecord> blockchainList = new LinkedBlockingDeque<>(); // created a LinkedBlockingDeque object to store verified BlockRecord.
    static ConcurrentHashMap<Integer, String> publicKeyList = new ConcurrentHashMap<>(3); // created a ConcurrentHashMap object to store three processes' public key

    public static void main(String[] args) {
        processID = args.length == 1 ? Integer.parseInt(args[0]) : 0; // assigned a value to processID according to the argument it passed in.

        // created a BlockingQueue object to store unverified block (BlockRecord class implemented Comparable)
        BlockingQueue<BlockRecord> unverifiedBlockList = new PriorityBlockingQueue<>(12);

        new PortNumber().setAllPorts(); // created a PortNumber object and invoked setAllPorts() method.

        new Thread(new PublicKeyServer()).start(); // start PublicKeyServer
        new Thread(new UnverifiedBlockServer(unverifiedBlockList)).start();// start UnverifiedBlockServer
        new Thread(new BlockChainServer()).start();// start BlockChainServer
        // start ProcessServer. This server will receive message once process 2 run. This server will generate Keys and multicast public keys to PublicKeyServer.
        new Thread(new ProcessServer()).start();

        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        try {
            // when process 2 run, it will send a message to three ProcessServers
            // (when ProcessServer got the message, it will generate public/private keys, and multicast to PublicKeyServer,
            // When PublicServer got 3 public keys, it then will call consoleCommand).
            if (processID == 2) {  // if processID is 2
                for (int i = 0; i < processNumber; i++) {
                    Socket socket = new Socket(serverName, PortNumber.processBasePort + i); // create a socket object and connect to ProcessServer
                    PrintStream writeToServer = new PrintStream(socket.getOutputStream()); // create a PrintStream object
                    writeToServer.println("All Processes are Ready"); // send a message to ProcessServer
                    writeToServer.flush();
                    socket.close(); // close socket
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        // create a UnverifiedBlockConsumer object, and create a Thread object to start it.
        // Once the UnverifiedBlockServer added an unverified block into the unverifiedBlockList,
        // the UnverifiedBlockConsumer will pop the block from the list and attempts to verify it.
        new Thread(new UnverifiedBlockConsumer(unverifiedBlockList)).start();
    }

    // This method is invoked by PublicKeyServer class after PublicKeyServer received public keys from three processes and stored them in ConcurrentHashMap.
    public static void consoleCommand() {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in)); // create a BufferedReader object to read input message
            do {
                System.out.println("\nThere are 4 options: ");
                System.out.println("1) Enter C for Credit");
                System.out.println("2) Enter R for reading a file (or \"R filename\" to read another files)");
                System.out.println("3) Enter V for verifying the entire blockchain ");
                System.out.println("4) Enter L for listing blockchain ");

                String input = in.readLine(); // read input

                // if input string is C, then check each BlockRecord in the blockchainList
                if (input.equals("C")) {
                    int p0 = 0;
                    int p1 = 0;
                    int p2 = 0;

                    if (!blockchainList.isEmpty()) {
                        for (BlockRecord b : blockchainList) {
                            if (b.getVerifiedProcessID().equals("0")) {
                                p0 += 1;
                            }
                            if (b.getVerifiedProcessID().equals("1")) {
                                p1 += 1;
                            }
                            if (b.getVerifiedProcessID().equals("2")) {
                                p2 += 1;
                            }
                        }
                    }
                    System.out.printf("Verification credit: P0 = %d, P1 = %d, P2 = %d\n\n", p0, p1, p2); // dispaly the verified credit for each process
                }

                // if input string is "R" or "R fileName"
                if (input.startsWith("R")) {
                    // For each process, if the input is only "R", then it will read its own local input, for example, input "R" in process 0, will read file "BlockInput0.txt"
                    // So, if input is "R", String fileName will invoke getFileName() method to get its default file
                    // If the input is "R fileName", then , then String fileName = fileName
                    String fileName = input.equals("R") ? getFileName(processID) : input.split(" ")[1];

                    unverifiedBlockClient(fileName); // call unverifiedBlockClient() method to read the file and generate unverified blocks, and then multicast to all processes

                    // Since read a file, put them in a unverified block, and verify them is a long process, so I set the sleep time to 10 seconds
                    try {
                        Thread.sleep(10000); // sleep 10000
                    } catch (InterruptedException e) { }
                }

                if (input.equals("V")) {
                    if (blockchainList.size() > 1) {
                        boolean verify = verifiedBlockchain(); // call verifiedBlockchain() to verify the entire blockchainList
                        System.out.printf("Blocks 1 - %d in the blockchain %s\n", blockchainList.size() - 1, verify ? "have been verified" : "is invalid");
                    } else {
                        System.out.println("No new blockchain adding, please enter R first");
                    }
                }

                // List each Block record in the blockchainList
                if (input.equals("L")) {
                    Iterator<BlockRecord> iterator = blockchainList.descendingIterator();
                    while (iterator.hasNext()) {
                        BlockRecord blockRecord = iterator.next();
                        System.out.printf("%s. %s  %s\n", blockRecord.getBlockNumber(), blockRecord.getTimeStamp(), blockRecord.getInputString());
                    }
                }

            } while (true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String getFileName(int number) {
        String name = "BlockInput0.txt";
        if (number == 1) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
            }
            name = "BlockInput1.txt";
        }
        if (number == 2) {
            try {
                Thread.sleep(1500);
            } catch (InterruptedException e) {
            }
            name = "BlockInput2.txt";
        }
        return name;
    }

    public static void unverifiedBlockClient(String fileName) {
        System.out.println("Reading file: " + fileName); // display this message on console

        try {
            BufferedReader bufferedReader = new BufferedReader(new FileReader(fileName)); // create a BufferedReader object to read the local file
            String inputString;
            while ((inputString = bufferedReader.readLine()) != null) { // read a line of information, and if it's not null, then sleep for 1 second to avoid conflict.
                try {
                    Thread.sleep(1005);
                } catch (InterruptedException e) {
                }

                BlockRecord blockRecord = new BlockRecord(inputString); // create a BlockRecord object with the inputString


                // marshaling the blockRecord object to JSON format
                String unverifiedBlockString = new GsonBuilder().setPrettyPrinting().create().toJson(blockRecord);
                //multicast to all processes
                for (int i = 0; i < processNumber; i++) {
                    try {
                        Socket socket = new Socket(serverName, PortNumber.unverifiedBlockBasePort + i); // create a Socket with correct UnverifiedBlockServer port
                        PrintStream writeToServer = new PrintStream(socket.getOutputStream()); // ceate a PrintStream object
                        writeToServer.println(unverifiedBlockString); // sent the blockRecord in JSON format to UnverifiedBlockServer
                        writeToServer.flush();
                        socket.close(); // close the socket
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    // verify the entire blockchainList
    public static boolean verifiedBlockchain() {
        boolean verified = true;
        BlockRecord firstBlock = blockchainList.getFirst(); // get the dummy block
        System.out.println("Is Verifying.... \n- the Proof-of-Work SHA-256-String.. \n- the Hash created solves the puzzle.. " +
                "\n- the Signed-SHA256 signature.. \n- the Signed-BlockID signature..");

        try {
            Thread.sleep(500);
        } catch (InterruptedException e){}

        for (BlockRecord blockRecord : blockchainList) {
            if (!(blockRecord.getBlockID().equals(firstBlock.getBlockID()))) { // if the block is not dummy block
                // verify the Proof-Work SHA256 String
                boolean verifiedWinnerHash = checkWinnerHash(blockRecord);
                // verify the winner hash String
                boolean verifiedHashSolvesPuzzle = Integer.parseInt(blockRecord.getWinnerHash().substring(0, 4), 16) < 20000;
                // verified the signed SHA256 (Proof-Work hash) by invoking the function verifySignaturePublicKey() in Util class
                boolean verifiedSignedSHA256 = Util.verifySignaturePublicKey(blockRecord.getWinnerHash(), blockRecord.getWinnerHashSignature(), Blockchain.publicKeyList.get(Integer.parseInt(blockRecord.getVerifiedProcessID())));
                // verified the signed block ID by invoking the function verifySignaturePublicKey() in Util class
                boolean verifiedSignedBlockID = Util.verifySignaturePublicKey(Util.getSHA256Hash(blockRecord.getBlockID()), blockRecord.getBlockIDSignature(), Blockchain.publicKeyList.get(Integer.parseInt(blockRecord.getCreatedProcessID())));

                // If any one of them is false, then verified is false
                if (!verifiedWinnerHash || !verifiedHashSolvesPuzzle || !verifiedSignedSHA256 || !verifiedSignedBlockID) {
                    verified = false;
                    break;
                }
            }
        }
        return verified;
    }


    public static boolean checkWinnerHash(BlockRecord blockRecord) {
        // concatenate the 3 Strings, invoke getSHA256Hash() from Util to get a new SHA256 hash String
        String produceSHA256Hash = Util.getSHA256Hash(blockRecord.getPreviousHash() + blockRecord.getInputString() + blockRecord.getRandSeed());

        return produceSHA256Hash.equals(blockRecord.getWinnerHash()); // compared the new SHA256 hash String (produceSHA256Hash) with the winnerHash, return true if they are true, or else , false.
    }

}

// When ProcessServer receive message, it will create keys and multicast public key to PublicKeyServer
class ProcessServer implements Runnable {
    @Override
    public void run() {
        System.out.println("Starting Process Server at the process 4740"); // display message on console
        try {
            ServerSocket serverSocket = new ServerSocket(PortNumber.processPort, 6); // create an ServerSocket object
            while (true) {
                Socket sock = serverSocket.accept(); //waiting for clients to connect
                new Thread(() -> { // create a new Thread object to handle the request from a client
                    try {
                        BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream())); // create a BufferedReader object to read message from client
                        String data = in.readLine(); // read message
                        if (data.equals("All Processes are Ready")) { // if got correct message from client
                            System.out.println("\nAll Processes are Ready\n"); // display this message on console
                            publicKeyClient(); // call publicKeyClient method to send public key string to PublicKeyServer
                        }
                        sock.close(); // close socket
                    } catch (Exception x) {
                        x.printStackTrace();
                    }
                }).start();
            }
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    // This method will send public key to PublicKeyServer
    public void publicKeyClient() {
        String publicKeyString = generatePublicKeyString(); // call generatePublicKeyString to get public key string
        if (publicKeyString != null) { // if publicKeyString is not null
            for (int i = 0; i < Blockchain.processNumber; i++) {
                try {
                    Socket socket = new Socket(Blockchain.serverName, PortNumber.publicKeyBasePort + i); // create a client socket
                    PrintStream writeToServer = new PrintStream(socket.getOutputStream()); // create a PrintStream object to send message to PublicKeyServer
                    writeToServer.println("processNumber=" + Blockchain.processID); // sent process ID to PublicKeyServer
                    writeToServer.println("publicKey=" + publicKeyString); // sent public key string to PublicKeyServer
                    writeToServer.flush();
                    socket.close(); // close socket
                } catch (Exception e) {
                }
            }
        }
    }

    public String generatePublicKeyString() {
        KeyPairGenerator keyGenerator = null;
        SecureRandom rng = null;
        try {
            keyGenerator = KeyPairGenerator.getInstance("RSA"); // get a KeyPairGenerator object that will generate private and public keys with the "RSA" algorithm
            rng = SecureRandom.getInstance("SHA1PRNG", "SUN"); // get a SecureRandom object with specific algorithm
        } catch (Exception e) {
            e.printStackTrace();
        }
        rng.setSeed(new Random().nextInt(1000)); // re-seed the rng
        keyGenerator.initialize(1024, rng); // initialize the keyGenerator
        KeyPair keyPair = keyGenerator.generateKeyPair(); // get a KeyPair object

        PublicKey publicKey = keyPair.getPublic(); // get the PublicKey from the keyPair
        Blockchain.privateKey = keyPair.getPrivate(); // get the privateKey from the keyPair, and assign it to the privateKey in Blockchain class

        byte[] bytePublicKey = publicKey.getEncoded(); // get the public key in encoding format
        String stringPublicKey = Base64.getEncoder().encodeToString(bytePublicKey); // convert the bytePubicKey to String format

        return stringPublicKey; // return the public key string
    }
}

class Util {

    // Because the dummy block also need the key to create its parameters, so this method is invoked by PublicKeyServer class
    // after PublicKeyServer received public keys from three processes and stored them in ConcurrentHashMap).
    public static BlockRecord createDummyBlock() {
        BlockRecord dummyBlock = new BlockRecord("Hongli Xue 0000.00.00 000-00-0000 0000 0000 00000"); // create a dummy block with fake information
        dummyBlock.setPreviousHash("0"); // set the previous hash of the dummy block to "0"

        for (int i = 1; i < 100; i++) { // the dummy block is important, so I gave it 100 chances to solve the puzzle
            String randString = Util.randomAlphaNumeric(8); // get a new random string
            String outHash = getSHA256Hash(dummyBlock.getInputString() + randString); // generate a SHA-256 hash

            int workNumber = Integer.parseInt(outHash.substring(0, 4), 16); // get a value Between 0 and 65535
            if (workNumber < 20000) { // if the workNumber is less than 20000, then puzzle solved
                dummyBlock.setBlockNumber(0); // dummy block set block number to 0
                dummyBlock.setWinnerHash(outHash); // dummy block set the proof-of-work hash
                dummyBlock.setRandSeed(randString);//dummy block set the rand seed value
                break; // if the puzzle solved, break the loop
            }
        }
        dummyBlock.setVerifiedProcessID(10); // set dummy block's verified process ID to 10 because I don't want it to be counted to the credit in console command
        return dummyBlock; // return dummy block
    }

    // check signature with pubic key
    public static boolean verifySignaturePublicKey(String data, String signatureString, String publicKeyString) {
        boolean verified = false;
        try {
            byte[] signatureBytes = Base64.getDecoder().decode(signatureString); // convert the signatureString to byte format
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString); // convert the public key string to byte format
            X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKeyBytes); // create a X509EncodedKeySpec object with the given encoded public key
            KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // create a KeyFactory object that will use to convert public key
            PublicKey publicKey = keyFactory.generatePublic(publicSpec); // generate a PublicKey object with the provided publicSpec

            Signature signature = Signature.getInstance("SHA1withRSA"); // create a Signature object with specific algorithm
            signature.initVerify(publicKey);  //initialize it for verifying
            signature.update(data.getBytes()); // update the data that in byte format to be verified

            verified = signature.verify(signatureBytes); // verified the signature
        } catch (Exception e) {
            e.printStackTrace();
        }
        return verified;
    }

    // sign data
    public static String getSignatureString(String data) {
        String signatureString = null;
        try {
            Signature signature = Signature.getInstance("SHA1withRSA");// create a Signature object with specific algorithm
            signature.initSign(Blockchain.privateKey); // initialize signature with PrivateKey for signing
            signature.update(data.getBytes()); // update the data that in byte format to be verified
            byte[] signatureByte = signature.sign(); // sign data
            signatureString = Base64.getEncoder().encodeToString(signatureByte); // convert signatureByte to String format
        } catch (Exception e) {
            e.printStackTrace();
        }
        return signatureString;
    }

    public static String getSHA256Hash(String data) {
        String hashString = null;
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256"); // create a MessageDigest object that implemented SHA-256 algorithm
            messageDigest.update(data.getBytes()); // update the messageDigest using the pass in data in byte format
            byte inputDataByte[] = messageDigest.digest(); // do hash computation to get the hash value, and assigned it to inputDataByte[]
            hashString = ByteArrayToString(inputDataByte); // convert the inputDataByte to String format


        } catch (Exception e) {
            e.printStackTrace();
        }

        return hashString;
    }

    // this function convert a byte array to String format
    public static String ByteArrayToString(byte[] ba){
        StringBuilder hex = new StringBuilder(ba.length * 2);
        for(int i=0; i < ba.length; i++){
            hex.append(String.format("%02X", ba[i]));
        }
        return hex.toString();
    }

    // this function generate a random String
    public static String randomAlphaNumeric(int count) {
        final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder builder = new StringBuilder(); // create a StringBuilder object
        while (count-- != 0) {
            int character = (int) (Math.random() * ALPHA_NUMERIC_STRING.length()); // randomly generate an integer
            builder.append(ALPHA_NUMERIC_STRING.charAt(character)); // get 1 character by using charAt() function, and append it to the builder
        }
        return builder.toString();
    }

    // checking if the blockRecord is in the blockchainList
    public static boolean isBlockInList(BlockRecord blockRecord){
        boolean isExisted = false;
        for (BlockRecord b : Blockchain.blockchainList) {
            if (b.getBlockID().equals(blockRecord.getBlockID())) {
                isExisted = true;
                break;
            }
        }
        return isExisted;
    }
}

class BlockChainServer implements Runnable {

    @Override
    public void run() {
        System.out.println("Starting the Blockchain server " + PortNumber.blockchainPort);
        try {
            ServerSocket serverSocket = new ServerSocket(PortNumber.blockchainPort, 6);  // create a ServerSocket object with specific port number
            while (true) {
                Socket socket = serverSocket.accept(); // waiting for request from client (UnverifiedBlockConsumer)
                new Thread(() -> { // create a new Thread to handle the client's request
                    try {
                        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream())); // create a BufferedReader object wrap with socket input stream
                        StringBuilder stringBuilder = new StringBuilder(); // create a StringBuilder object to append the message from client
                        String data;
                        while ((data = in.readLine()) != null) {
                            stringBuilder.append(data);
                        }

                        Gson gson = new GsonBuilder().setPrettyPrinting().create(); // create a gson object
                        BlockRecord blockRecord = gson.fromJson(stringBuilder.toString(), BlockRecord.class); // unmarshal the received verified block into a BlockRecord object

                        boolean isExisted = Util.isBlockInList(blockRecord); // double check if the blockRecord is in the blockchainList

                        if (!isExisted) {  // if it's not in the list
                            Blockchain.blockchainList.put(blockRecord); // adding the blockRecord to blockchainList
                            Blockchain.blockNumber++;  // add 1 to current blockNumber in Blockchain class for next use
                            if (Blockchain.processID == 0) { // process 0 will write the updated blockchainList to disk
                                WriteJSON("BlockchainLedger.json"); // call wirteJson() function to write it to disk
                            }
                            System.out.printf("** NEW BLOCKCHAIN ** %s. %s %s (Created by %s, Verified by %s)\n",blockRecord.getBlockNumber(),blockRecord.getFirstName(), blockRecord.getLastName(), blockRecord.getCreatedProcessID(), blockRecord.getVerifiedProcessID());
                        }
                        socket.close(); // close socket
                    } catch (Exception x) {
                        x.printStackTrace();
                    }
                }).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public void WriteJSON(String filename) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create(); // create a Gson object

        try (FileWriter writer = new FileWriter(filename)) { // create a FileWriter object
            gson.toJson(Blockchain.blockchainList, writer); // write the list to disk
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

class UnverifiedBlockConsumer implements Runnable {
    BlockingQueue<BlockRecord> unverifiedBlockList;

    public UnverifiedBlockConsumer(BlockingQueue<BlockRecord> unverifiedBlockList) {
        this.unverifiedBlockList = unverifiedBlockList;
    }

    @Override
    public void run() {
        System.out.println("\nStarting the Unverified Block Priority Queue Consumer thread.\n");
        try {
            while (true) {
                BlockRecord blockRecord = unverifiedBlockList.take(); // Once unverifiedBlockList received unverified blocks, popped a block from it and assigned to blockRecord
                System.out.println("[Consumer got a unverified block] " + blockRecord.getFirstName() + " " + blockRecord.getLastName() );

                // check if the blockRecord is in the blockchainList
                boolean isInList = Util.isBlockInList(blockRecord);

                if (!isInList) { // if it's not in the blockchainlist
                    // verified the signed block ID by invoking the function verifySignaturePublicKey() in Util class
                    boolean verifiedSignedBlockID = Util.verifySignaturePublicKey(Util.getSHA256Hash(blockRecord.getBlockID()), blockRecord.getBlockIDSignature(),
                            Blockchain.publicKeyList.get(Integer.parseInt(blockRecord.getCreatedProcessID())));
                    // verified SHA256 hash string
                    boolean verifiedSHA256Hash = verifySHA256Hash(blockRecord);

                    // if verifiedSignedBlockID and verifiedSHA256Hash are true
                    if (verifiedSignedBlockID && verifiedSHA256Hash) {
                        doWork(blockRecord); // call doWork() to solve the puzzle
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void doWork(BlockRecord blockRecord) {

        String previousBlockHashString = Blockchain.blockchainList.getLast().getWinnerHash(); // get Proof-Of-Work hash from the previous block in blockchainList
        blockRecord.setPreviousHash(previousBlockHashString); // set previousHash for blockRecord

        try {
            // do work to solve puzzle
            for (int i = 1; i < 20; i++) {
//                boolean isBlockExisted = (blockRecord.getBlockID().equals(Blockchain.blockchainList.getLast().getBlockID())) ? true : false;
                boolean isBlockModified = blockRecord.getVerifiedProcessID() != null ? true : false; // check if blockRecord has been modified

                if (!isBlockModified) { // if it's not been modified
                    String randString = Util.randomAlphaNumeric(8); // get a new random String
                    String concatThreeString = blockRecord.getPreviousHash() + blockRecord.getInputString() + randString; //concatenate the previous hash, input data, and randString together
                    String proofOfWorkHash = Util.getSHA256Hash(concatThreeString); // generate a SHA256 hash with concatThreeString

                    int workNumber = Integer.parseInt(proofOfWorkHash.substring(0, 4), 16); // get an integer from SHA256Hash
                    if (workNumber < 20000) { // if workNumber is less than 20000, then puzzle solved
                            blockRecord.setBlockNumber(Blockchain.blockNumber); // set blockNumber into this blockRecord
                            blockRecord.setVerifiedProcessID(Blockchain.processID);// set verifiedProcessID into this blockRecord
                            blockRecord.setRandSeed(randString); // set randSeed into this blockRecord
                            blockRecord.setWinnerHash(proofOfWorkHash); // set winnerHash into this blockRecord
                            String workHashSignature = Util.getSignatureString(proofOfWorkHash); // get a signature string with Proof-Of-Work hash
                            blockRecord.setWinnerHashSignature(workHashSignature); // set winnerHashSignature into this blockRecord
                            doMultiCast(blockRecord); // call doMultiCast() to send this verified block to (all processes) BlockChainServer
                            break;
                    }
                    Thread.sleep(500);
                } else {
                    boolean isInBlockChain = Util.isBlockInList(blockRecord); // check if this updated blockchain is in the blockchainList
                    if (!isInBlockChain){ // if it's not in the blockchainList
                        blockRecord.setVerifiedProcessID(null); // set the verifiedProcessID to null
                        doWork(blockRecord); // then doWork() again to verify it.
                    }
                    break;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void doMultiCast(BlockRecord blockRecord) {
        for (int j = 0; j < Blockchain.processNumber; j++) {
            try {
                Socket socket = new Socket(Blockchain.serverName, PortNumber.blockchainBasePort + j); // create a socket object to connect the BlockChainServer specified by serverName and portNumber
                PrintStream writeToServer = new PrintStream(socket.getOutputStream()); // create a PrintStream object
                writeToServer.println(new GsonBuilder().setPrettyPrinting().create().toJson(blockRecord)); // marshaling the blockRecord to JSON and send to BlockChainServer
                writeToServer.flush();
                socket.close(); // close the socket
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    // Verify the SHA-256 hash of the input data
    private boolean verifySHA256Hash(BlockRecord blockRecord) {
        String dataHash = Util.getSHA256Hash(blockRecord.getInputString()); // re-generate the SHA-256 hash string with the same data
        return dataHash.equals(blockRecord.getSHA256InputData()); // compare the dataHash with sha256InputData, return true if they are the same, or else return false.
    }
}

class UnverifiedBlockServer implements Runnable {
    BlockingQueue<BlockRecord> unverifiedBlockList;

    public UnverifiedBlockServer(BlockingQueue<BlockRecord> unverifiedBlockList) {
        this.unverifiedBlockList = unverifiedBlockList;
    }

    public void run() {
        System.out.println("Starting UnverifiedBlock Server at the process " + PortNumber.unverifiedBlockPort); // display this message on console
        try {
            ServerSocket serverSocket = new ServerSocket(PortNumber.unverifiedBlockPort, 6); // create a ServerSocket object with specific port
            while (true) {
                Socket sock = serverSocket.accept(); // waiting for client's request
                new Thread(() -> { // create a new Thread object to handle the request from a client
                    try {
                        BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream())); // create a BufferedReader object
                        StringBuilder stringBuilder = new StringBuilder(); // create a StringBuilder object
                        String data; // define a String variable
                        while ((data = in.readLine()) != null) {
                            stringBuilder.append(data); // get the marshaled unverifief block
                        }

                        Gson gson = new GsonBuilder().setPrettyPrinting().create(); // create a gson object
                        BlockRecord blockRecord = gson.fromJson(stringBuilder.toString(), BlockRecord.class);  // unmarshal the received unverified block into a BlockRecord object
                        unverifiedBlockList.put(blockRecord); // adding the blockRecord to unverifiedBlockList
                        System.out.printf("Added a record to unverified blocks: (Created by %s) %s\n", blockRecord.getCreatedProcessID(), blockRecord.getFirstName() + " " + blockRecord.getLastName());

                        sock.close();
                    } catch (Exception x) {
                        x.printStackTrace();
                    }
                }).start();
            }
        } catch (IOException ioe) {
            System.out.println(ioe);
        }
    }
}

// This class is in charge of storing the public keys from three processes to the list in Blockchain class,
// creating dummy block, and calling the console command method in Blockchain after all keys received.
class PublicKeyServer implements Runnable {
    @Override
    public void run() {
        System.out.println("Starting Public Key Server at the process " + PortNumber.publicKeyPort); // display message on console
        try {
            ServerSocket serverSocket = new ServerSocket(PortNumber.publicKeyPort, 6); // create a ServerSocket object
            while (true) {
                Socket sock = serverSocket.accept(); // waiting for clients to connect
                new Thread(() -> { // create a new Thread object to handle the request from a client
                    try {
                        BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream())); // create a BufferedReader object
                        String data; // define a String
                        Integer pid = null; // define a pid and set value as null by defualt, it will use to store process ID
                        String key = null;  // define a String and set value as null, it will store public key string
                        while ((data = in.readLine()) != null) {  // get a line of message, and store it in data, and if the data is not null
                            if (data.startsWith("processNumber")) { // if the data start with processNumber
                                String[] strings1 = data.split("="); // get a string array from data
                                pid = Integer.parseInt(strings1[1]); // get process ID and store it in pid
                            }
                            if (data.startsWith("publicKey")) { // if the data starts with publicKey
                                String[] strings2 = data.split("="); // get a string array from data
                                key = strings2[1]; // get public key string from strings2[1] and assigned it to key
                            }
                        }

                        if (pid != null && key != null) {  // if pid and key are not null
                            Blockchain.publicKeyList.put(pid, key); // store the process ID and associated public key string in list
                            System.out.println("Got key from process " + pid); // display message on console

                            if (Blockchain.publicKeyList.size() == 3) { // if got three keys from three processes
                                System.out.println("Three keys are ready!\n"); // display this message on console

                                Blockchain.blockchainList.add(Util.createDummyBlock()); // created the dummy block and add it to blockchainList
                                if (Blockchain.blockchainList.size() == 1) { // make sure the dummy block has been successfully added to list
                                    System.out.println("----Create A Dummy Block in Blockchain List-----"); // print this message on console
                                }
                                Blockchain.consoleCommand(); // since three keys are ready, call consoleCommand method on Blockchain class.
                            }
                        }
                        sock.close(); // close socket
                    } catch (Exception x) { // throw an exception
                        x.printStackTrace(); // print the exception message on console
                    }
                }).start();
            }
        } catch (IOException ioe) {// throw an exception
            System.out.println(ioe); // display the error message on console.
        }

    }
}

class PortNumber {
    public static final int publicKeyBasePort = 4710; // set the base port for PublicKeyServer
    public static final int unverifiedBlockBasePort = 4820; // set the base port for UnverifiedblockServer
    public static final int blockchainBasePort = 4930; // set the base port for BlockChainServer
    public static final int processBasePort = 4940; // set the base port for ProcessServer

    public static int publicKeyPort;
    public static int unverifiedBlockPort;
    public static int blockchainPort;
    public static int processPort;

    public void setAllPorts() {
        publicKeyPort = publicKeyBasePort + Blockchain.processID; // set publicKeyPort for each process
        unverifiedBlockPort = unverifiedBlockBasePort + Blockchain.processID;// set unverifiedBlockPort for each process
        blockchainPort = blockchainBasePort + Blockchain.processID;// set blockchainPort for each process
        processPort = processBasePort + Blockchain.processID;// set processPort for each process
    }
}

class BlockRecord implements Comparable<BlockRecord> {
    private String blockNumber;
    private String blockID;
    private String createdProcessID;
    private String verifiedProcessID;
    private String timeStamp;
    private String previousHash;
    private String winnerHash;
    private String randSeed;
    private String inputString;
    private String SHA256InputData;
    private String blockIDSignature;
    private String winnerHashSignature;
    private String firstName;
    private String lastName;
    private String birth;
    private String diagnosis;
    private String ssnNumber;
    private String treatment;
    private String rx;

    public BlockRecord(String inputString) {  // construct
        this.inputString = inputString;
        String[] inputData = inputString.split(" +");
        firstName = inputData[0];
        lastName = inputData[1];
        birth = inputData[2];
        ssnNumber = inputData[3];
        diagnosis = inputData[4];
        treatment = inputData[5];
        rx = inputData[6];

        verifiedProcessID = null;

        blockID = UUID.randomUUID().toString(); // set blockID

        String SHA256UUIDString = Util.getSHA256Hash(blockID);  // get a SHA256 hash String of the blockID
        blockIDSignature = Util.getSignatureString(SHA256UUIDString); // get the blockID signature String by invoking getSignatureString() method in Util class

        createdProcessID = String.valueOf(Blockchain.processID);  // set creatingProcessID

        timeStamp = String.format("%1$s %2$tF.%2$tT", "", new Date()) + Blockchain.processID; // set timeStamp with current time + processID

        SHA256InputData = Util.getSHA256Hash(inputString);  // get an SHA256 hash string of the inputString by invoking getSHA256Hash() method in Util class
    }

    @Override
    public int compareTo(BlockRecord b) {
        String s1 = getTimeStamp();
        String s2 = b.getTimeStamp();
        if (s1 == s2) {
            return 0;
        }
        if (s1 == null) {
            return -1;
        }
        if (s2 == null) {
            return 1;
        }
        return s1.compareTo(s2);
    }

    public String getBlockIDSignature() {
        return blockIDSignature;
    }

    public void setVerifiedProcessID(String verifiedProcessID) {
        this.verifiedProcessID = verifiedProcessID;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public String getWinnerHashSignature() {
        return winnerHashSignature;
    }

    public void setWinnerHashSignature(String winnerHashSignature) {
        this.winnerHashSignature = winnerHashSignature;
    }

    public String getBlockID() {
        return blockID;
    }

    public String getCreatedProcessID() {
        return createdProcessID;
    }

    public String getTimeStamp() {
        return timeStamp;
    }

    public String getSHA256InputData() {
        return SHA256InputData;
    }

    public String getPreviousHash() {
        return previousHash;
    }

    public void setPreviousHash(String previousHash) {
        this.previousHash = previousHash;
    }

    public String getWinnerHash() {
        return winnerHash;
    }

    public void setWinnerHash(String winnerHash) {
        this.winnerHash = winnerHash;
    }

    public String getRandSeed() {
        return randSeed;
    }

    public void setRandSeed(String randSeed) {
        this.randSeed = randSeed;
    }

    public String getInputString() {
        return inputString;
    }

    public String getBlockNumber() {
        return blockNumber;
    }

    public void setBlockNumber(int blockNumber) {
        this.blockNumber = String.valueOf(blockNumber);
    }

    public String getVerifiedProcessID() {
        return verifiedProcessID;
    }

    public void setVerifiedProcessID(int verifiedProcessID) {
        this.verifiedProcessID = String.valueOf(verifiedProcessID);
    }
}