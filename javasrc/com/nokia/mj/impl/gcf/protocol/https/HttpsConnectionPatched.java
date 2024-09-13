/**
 * Copyright (c) 2024 Arman Jussupgaliyev
 */

package com.nokia.mj.impl.gcf.protocol.https;

import java.io.IOException;

import javax.microedition.io.HttpsConnection;
import javax.microedition.io.SecureConnection;
import javax.microedition.io.SecurityInfo;
import javax.microedition.io.SocketConnection;
import javax.microedition.io.StreamConnection;

import ru.nnproject.tls.SSLSocket;

public class HttpsConnectionPatched extends HttpConnectionPatched implements HttpsConnection {

	public SecurityInfo getSecurityInfo() throws IOException {
		if (socket instanceof SecureConnection) {
			((SecureConnection) socket).getSecurityInfo();
		}
		return null;
	}

	public String getProtocol() {
		return "https";
	}
	
	protected int getDefaultPort() {
		return 443;
	}
	
	public int getPort() {
		if(port != 0) {
			return port;
		}
		return 443;
	}

	protected StreamConnection openSocket(boolean timeout, String socketOptions) throws IOException {
		openNetworkInterfaceAndUpdateProxyInformation();
		if (patchedSocket) {
			return new SSLSocket(getHost(), getPort());
		}
		SocketConnection connection = (SocketConnection) new com.nokia.mj.impl.gcf.protocol.ssl.Connection()
				.setParameters2("//" + getHost() + ":" + getPort() + socketOptions + apn, 3, timeout);

		return connection;
	}

}
