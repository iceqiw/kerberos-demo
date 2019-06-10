package com.kerberos.demo;

import org.ietf.jgss.*;
import java.net.Socket;
import java.io.IOException;
import java.io.DataInputStream;
import java.io.DataOutputStream;

public class ClientDemo {

    public static void main(String[] args)
            throws IOException, GSSException {

        System.setProperty("java.security.krb5.realm","ZTWU.COM");
        System.setProperty("java.security.krb5.kdc","hadoop03.ztwu.com");
        System.setProperty("javax.security.auth.useSubjectCredsOnly","false");
        System.setProperty("java.security.krb5.conf", "D:\\data\\idea\\java\\private\\github-self-workspace\\kerberos-demo\\src\\main\\resources\\krb5.conf");
        System.setProperty("java.security.auLoginContextth.login.config","D:\\data\\idea\\java\\private\\github-self-workspace\\kerberos-demo\\src\\main\\resources\\demo.conf");

        String server = "sample/hadoop03.ztwu.com";

        String hostName = "127.0.0.1";

        int port = 8090;

        Socket socket = new Socket(hostName, port);

        DataInputStream inStream =
                new DataInputStream(socket.getInputStream());

        DataOutputStream outStream =
                new DataOutputStream(socket.getOutputStream());

        System.out.println("Connected to server "

                + socket.getInetAddress());

        Oid krb5Oid = new Oid("1.2.840.113554.1.2.2");

        GSSManager manager = GSSManager.getInstance();

        GSSName serverName = manager.createName(server, null);

        GSSContext context = manager.createContext(serverName,

                krb5Oid,

                null,

                GSSContext.DEFAULT_LIFETIME);

        context.requestMutualAuth(true);  // Mutual authentication

        context.requestConf(true);  // Will use confidentiality later

        context.requestInteg(true); // Will use integrity later

// Do the context eastablishment loop

        byte[] token = new byte[0];

        while (!context.isEstablished()) {

            // token is ignored on the first call

            token = context.initSecContext(token, 0, token.length);

            // Send a token to the server if one was generated by

            // initSecContext

            if (token != null) {

                System.out.println("Will send token of size "

                        + token.length

                        + " from initSecContext.");

                outStream.writeInt(token.length);

                outStream.write(token);

                outStream.flush();

            }

            // If the client is done with context establishment

            // then there will be no more tokens to read in this loop

            if (!context.isEstablished()) {

                token = new byte[inStream.readInt()];

                System.out.println("Will read input token of size "

                        + token.length

                        + " for processing by initSecContext");

                inStream.readFully(token);

            }

        }

        System.out.println("Context Established! ");

        System.out.println("Client is " + context.getSrcName());

        System.out.println("Server is " + context.getTargName());

        if (context.getMutualAuthState())

            System.out.println("Mutual authentication took place!");

        byte[] messageBytes = "Hello There!\0".getBytes();

        MessageProp prop =  new MessageProp(0, true);

        token = context.wrap(messageBytes, 0, messageBytes.length, prop);

        System.out.println("Will send wrap token of size " + token.length);

        outStream.writeInt(token.length);

        outStream.write(token);

        outStream.flush();

        token = new byte[inStream.readInt()];

        System.out.println("Will read token of size " + token.length);

        inStream.readFully(token);

        context.verifyMIC(token, 0, token.length,

                messageBytes, 0, messageBytes.length,

                prop);

        System.out.println("Verified received MIC for message.");

        System.out.println("Exiting...");

        context.dispose();

        socket.close();

    }

}