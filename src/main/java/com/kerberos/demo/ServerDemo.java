package com.kerberos.demo;

import org.ietf.jgss.*;
import java.io.*;
import java.net.Socket;
import java.net.ServerSocket;
public class ServerDemo  {

    public static void main(String[] args)
            throws IOException, GSSException {

        System.setProperty("java.security.krb5.realm","ZTWU.COM");
        System.setProperty("java.security.krb5.kdc","hadoop03.ztwu.com");
        System.setProperty("javax.security.auth.useSubjectCredsOnly","false");
        System.setProperty("java.security.auth.login.config","D:\\data\\idea\\java\\private\\github-self-workspace\\kerberos-demo\\src\\main\\resources\\demo.conf");

        int localPort = 8090;
        ServerSocket ss = new ServerSocket(localPort);

        //通用安全服务API(Generic Security Services API, GSS-API)是由因特网工程小组(IETF)开发的一套标准API,
        // 以提供支持各种可插人安全机制的通用认证和安全消息接口。
        // GSS-API还允许使用通用接口开发应用认证，从而将用户同底层安全机制隔离开。
        GSSManager manager = GSSManager.getInstance();

        while (true) {

            System.out.println("Waiting for incoming connection...");
            Socket socket = ss.accept();

            DataInputStream inStream =
                    new DataInputStream(socket.getInputStream());

            DataOutputStream outStream =
                    new DataOutputStream(socket.getOutputStream());

            System.out.println("Got connection from client "
                    + socket.getInetAddress());

            GSSContext context = manager.createContext((GSSCredential)null);

            byte[] token = null;

            while (!context.isEstablished()) {

                token = new byte[inStream.readInt()];

                System.out.println("Will read input token of size "

                        + token.length

                        + " for processing by acceptSecContext");

                inStream.readFully(token);

                token = context.acceptSecContext(token, 0, token.length);

                if (token != null) {

                    System.out.println("Will send token of size "

                            + token.length

                            + " from acceptSecContext.");

                    outStream.writeInt(token.length);

                    outStream.write(token);

                    outStream.flush();

                }

            }

            System.out.print("Context Established! ");

            System.out.println("Client is " + context.getSrcName());

            System.out.println("Server is " + context.getTargName());

            if (context.getMutualAuthState())

                System.out.println("Mutual authentication took place!");

            MessageProp prop = new MessageProp(0, false);

            token = new byte[inStream.readInt()];

            System.out.println("Will read token of size "

                    + token.length);

            inStream.readFully(token);

            byte[] bytes = context.unwrap(token, 0, token.length, prop);

            String str = new String(bytes);

            System.out.println("Received data \""

                    + str + "\" of length " + str.length());

            System.out.println("Confidentiality applied: "

                    + prop.getPrivacy());

            prop.setQOP(0);

            token = context.getMIC(bytes, 0, bytes.length, prop);

            System.out.println("Will send MIC token of size "

                    + token.length);

            outStream.writeInt(token.length);

            outStream.write(token);

            outStream.flush();

            System.out.println("Closing connection with client "

                    + socket.getInetAddress());

            context.dispose();

            socket.close();

        }

    }

}
