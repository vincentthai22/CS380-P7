/**
 * Created by Vincent on 6/7/2017.
 */


import java.awt.*;
import java.io.*;
import java.util.Scanner;
import java.util.zip.CRC32;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import javax.crypto.*;


public class FileTransfer {

    private final int ACK_MESSAGE_FAILED = -1;
    private final int ACK_MESSAGE_SUCCESS = 0;


    public FileTransfer() {

    }

    public void makeKeys() {
        try {

            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);

            KeyPair keyPair = gen.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();

            PublicKey publicKey = keyPair.getPublic();

            try {
                ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(new File("public.bin")));
                objectOutputStream.writeObject(publicKey);
            } catch (Exception e) {
                e.printStackTrace();
            }

            try {
                ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(new File("private.bin")));
                objectOutputStream.writeObject(privateKey);
            } catch (Exception e) {
                e.printStackTrace();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("keys made");
    }

    public void serverMode(String arg1, String arg2) {

        try {
            InputStream inputStream;
            ObjectInputStream objectInputStream;
            OutputStream outputStream;
            ObjectOutputStream objectOutputStream;
            Message message;
            MessageType messageType;
            StartMessage startMessage;
            AckMessage ackMessage;
            Cipher cipher;
            Key session;
            long messageSize, chunkAmount, chunkSize;

            ServerSocket serverSocket = new ServerSocket(Integer.parseInt(arg2));

            for (; ; ) {

                Socket socket = serverSocket.accept();

                System.out.println("Connection established");
                inputStream = socket.getInputStream();
                objectInputStream = new ObjectInputStream(inputStream);
                outputStream = socket.getOutputStream();
                objectOutputStream = new ObjectOutputStream(outputStream);
                message = (Message) objectInputStream.readObject();
                messageType = message.getType();

                if (messageType == MessageType.START) {

                    PrivateKey privateKey;
                    int expSeq = 0, errorCheckIndex = 0, seqNum;
                    byte[] finalData;

                    try {

                        ObjectInputStream keyInputStream = new ObjectInputStream(new FileInputStream(new File(arg1)));  //retrieve private key
                        privateKey = (PrivateKey) keyInputStream.readObject();

                    } catch (Exception e) {
                        e.printStackTrace();
                        ackMessage = new AckMessage(ACK_MESSAGE_FAILED);     //key retrieval failed
                        objectOutputStream.writeObject(ackMessage);                     //break out of loop
                        break;
                    }

                    ackMessage = new AckMessage(ACK_MESSAGE_SUCCESS);
                    startMessage = (StartMessage) message;

                    objectOutputStream.writeObject(ackMessage);

                    cipher = Cipher.getInstance("RSA");
                    cipher.init(Cipher.UNWRAP_MODE, privateKey);

                    session = cipher.unwrap(startMessage.getEncryptedKey(), "AES", Cipher.SECRET_KEY);

                    messageSize = startMessage.getSize();
                    chunkSize = startMessage.getChunkSize();
                    chunkAmount = (long) Math.ceil((double) (messageSize / chunkSize));
                    finalData = new byte[(int) messageSize];

                    while (expSeq < chunkAmount) {

                        message = (Message) objectInputStream.readObject();
                        messageType = message.getType();

                        if (messageType == MessageType.CHUNK) {
                            byte[] data, decryptedData;
                            CRC32 cyclicRC = new CRC32();
                            Chunk messageChunk = (Chunk) message;
                            seqNum = messageChunk.getSeq();

                            if (seqNum == expSeq) {

                                data = messageChunk.getData();

                                cipher = Cipher.getInstance("AES");
                                cipher.init(Cipher.DECRYPT_MODE, session);

                                decryptedData = cipher.doFinal(data);
                                cyclicRC.update(decryptedData);

                                if (cyclicRC.getValue() == messageChunk.getCrc()) {
                                    expSeq += 1;

                                    for (byte bit : decryptedData) {
                                        if (errorCheckIndex == decryptedData.length)
                                            break;
                                        finalData[errorCheckIndex++] = bit;
                                    }

                                    ackMessage = new AckMessage(expSeq);
                                    System.out.println("Chunk received [" + expSeq + "/" + chunkAmount + "].");
                                } else {
                                    ackMessage = new AckMessage(seqNum);
                                }
                                objectOutputStream.writeObject(ackMessage);
                            }
                        } else if (messageType == MessageType.STOP) {
                            ackMessage = new AckMessage(ACK_MESSAGE_FAILED);
                            objectOutputStream.writeObject(ackMessage);
                            break;
                        }
                        if (expSeq == chunkAmount) {
                            FileOutputStream fileOutputStream = new FileOutputStream(new File("(2)"+startMessage.getFile()));
                            fileOutputStream.write(finalData);
                            fileOutputStream.close();
                            System.out.println("Transfer Complete\nOutput path: " + "(2)"+startMessage.getFile());
                        }

                    }
                    socket.close();
                } else if (messageType == MessageType.DISCONNECT) {
                    socket.close();

                }
//                break;

            }


        } catch (Exception e) {

        }

    }

    public void clientMode(String arg1, String arg2, String arg3) {
        boolean isTransferringFile = true, isValid = false;
        Cipher cipher;
        KeyGenerator keyGenerator;
        Key sessionKey;
        OutputStream outputStream;
        ObjectOutputStream objectOutputStream;
        InputStream inputStream;
        ObjectInputStream objectInputStream;
        PublicKey key = null;
        int chunkSize;
        byte[] session = null;

        Scanner kbd = new Scanner(System.in);
        try {
            while (isTransferringFile) {

                keyGenerator = KeyGenerator.getInstance("AES");
                keyGenerator.init(128);
                sessionKey = keyGenerator.generateKey();

                Socket socket = new Socket(arg2, Integer.parseInt(arg3));
                outputStream = socket.getOutputStream();
                objectOutputStream = new ObjectOutputStream(outputStream);
                inputStream = socket.getInputStream();
                objectInputStream = new ObjectInputStream(inputStream);

                objectOutputStream.flush();

                try {
                    ObjectInputStream publicKeyStream = new ObjectInputStream(new FileInputStream(new File(arg1)));
                    key = (PublicKey) publicKeyStream.readObject();
                    cipher = Cipher.getInstance("RSA");
                    cipher.init(Cipher.WRAP_MODE, key);
                    session= cipher.wrap(sessionKey);

                } catch (IOException e) {
                    e.printStackTrace();
                }
                File file = null;
                String path;

                for(;;) {
                    System.out.print("Enter path: ");
                    path = kbd.nextLine();
                    file = new File(path);
                    if (!file.exists()) {
                        System.out.println("Invalid file; please try again.");
                    } else {
                        break;
                    }
                }

                for(;;) {
                    System.out.print("Enter chunk size [1024]: ");
                    String size = kbd.nextLine();

                    if (size.length() < 1) {
                        chunkSize = 1024;
                        break;
                    } else {
                        try {
                            chunkSize = Integer.parseInt(size);
                            if(Integer.parseInt(size) % 2 == 1)
                                chunkSize++;
                            break;
                        } catch (Exception e) {
                            System.out.println("Invalid input; try again");
                        }
                    }
                }

                StartMessage startMessage = new StartMessage(path, session, chunkSize);
                objectOutputStream.writeObject(startMessage);

                long length = file.length();
                long chunkAmount = (long)Math.ceil(length / chunkSize);
                int seqNum = 0;

                InputStream fileInputStream = new FileInputStream(path);
                System.out.println("Sending: " + path + ". File size (byte): " + length + "\nSending " + chunkAmount);

                while (seqNum < chunkAmount) {
                    AckMessage ackMessage = (AckMessage) objectInputStream.readObject();
                    CRC32 md5Hash = new CRC32();

                    if (ackMessage.getSeq() == ACK_MESSAGE_FAILED) {
                        System.out.println("Transfer stopped");

                    } else {

                        if (ackMessage.getSeq() != seqNum) {
                            System.out.println("invalid acknowledgement");
                            System.exit(0);

                        } else {
                            byte[] data = new byte[chunkSize];
                            for (int i = 0; i < chunkSize; i++) {
                                data[i] = (byte) fileInputStream.read();
                            }
                            md5Hash.update(data);
                            int md5HashValue = (int) md5Hash.getValue();
                            cipher = Cipher.getInstance("AES");
                            cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
                            data = cipher.doFinal(data);
                            Chunk chunk = new Chunk(seqNum, data, md5HashValue);
                            objectOutputStream.writeObject(chunk);
                            seqNum+=1;
                            System.out.println("Chunks completed [" + seqNum + "/" + chunkAmount + "].");
                        }
                    }
                }

                System.out.println("Transfer Completed.\nGoodbye.");
                break;

            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public static void main(String[] args) {
        FileTransfer fileTransfer = new FileTransfer();


        if (args.length > 0) {
            switch (args[0]) {
                case "makekeys":
                    fileTransfer.makeKeys();
                    break;
                case "server":
                    if (args.length > 2) {
                        fileTransfer.serverMode(args[1], args[2]);

                    } else {
                        System.out.println("Incorrect arguments. \nGoodbye.");
                    }
                    break;
                case "client":
                    if (args.length > 3) {
                        fileTransfer.clientMode(args[1], args[2], args[3]);
                    }
                    break;
                default:
                    System.out.println("Invalid argszzz");
            }

        } else {

            System.out.println("Incorrect arguments. \nGoodbye");
        }


    }

}
