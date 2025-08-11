/**
 * Copyright (c) 2024 Arman Jussupgaliyev
 */
 
package ru.nnproject.tls;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.microedition.io.SecureConnection;
import javax.microedition.io.SecurityInfo;

import com.nokia.mj.impl.gcf.utils.UrlParser;
import com.nokia.mj.impl.rt.support.Finalizer;
import com.nokia.mj.impl.rt.support.Jvm;

public class SSLSocket implements SecureConnection {

	private static LibraryFinalizer libraryFinalizer;
	private final static Object globalLock;
	
	static {
		globalLock = new Object();
		try {
			Jvm.loadSystemLibrary("javannssl");
			_initLibrary();
			libraryFinalizer = new LibraryFinalizer();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	int handle;
	int inputState;
	int outputState;
	int connectState;
	private Finalizer finalizer;
	
	private String host;
	private int port;
	
	public SSLSocket(String host, int port) throws IOException {
		init("", host, port);
	}
	
	public SSLSocket(String aUrl) throws IOException {
		UrlParser url = new UrlParser("ssl:" + aUrl);
		init(aUrl, url.host, url.port);
	}
	
	private void init(String url, String host, int port) throws IOException {
		finalizer = registerFinalize();
		synchronized (globalLock) {
			handle = _new();
			this.host = host;
			this.port = port;
			int r = _set(handle, url, host, port);
			if (r != 0) {
				throw new IOException("Set host failed: " + r);
			}
			r = _initSsl(handle);
			if (r != 0) {
				throw new IOException("Init ssl failed: " + r);
			}
		}
	}
	
	public void connect() throws IOException{
		if (connectState != 0) return;
		connectState = 1;
		int r = _connect(handle);
		if (r != 0)
			throw new IOException("Connect error " + r);

		r = _handshake(handle);
		if (r != 0)
			throw new IOException("Handshake error " + r);
	}
	
	public InputStream openInputStream() throws IOException {
		if (connectState == 0)
			connect();
		if (inputState != 0)
			throw new IOException("Input already open");
		inputState = 1;
		return new InputStream() {

			public synchronized int read() throws IOException {
				if (handle == 0 || inputState == 2)
					throw new IOException("Closed");
				byte[] data = new byte[1];
				int r = _read(handle, data, 0, 1);
				if (r == 0) return -1;
				if (r < 0) {
					throw new IOException("Read error " + r);
				}
				return r;
			}
			
			public synchronized int read(byte[] buf, int off, int len) throws IOException {
				if (handle == 0 || inputState == 2)
					throw new IOException("Closed");
				if (len+off > buf.length || off < 0 || len < 0)
					throw new IllegalArgumentException();
				int r;
				if (off > 0) {
					byte[] temp = new byte[len];
					r = _read(handle, temp, 0, len);
					System.arraycopy(temp, 0, buf, off, r);
				} else {
					r = _read(handle, buf, off, len);
				}
				if (r == 0) return -1;
				if (r < 0) {
					throw new IOException("Read error " + r);
				}
				return r;
			}
			
			public void close() {
				inputState = 2;
			}
			
		};
	}

	public OutputStream openOutputStream() throws IOException {
		if (connectState == 0)
			connect();
		if (outputState != 0)
			throw new IOException("Output already open");
		outputState = 1;
		return new OutputStream() {

			public synchronized void write(int b) throws IOException {
				if (handle == 0 || outputState == 2)
					throw new IOException("Closed");
				byte[] data = new byte[] { (byte) b };
				int r = _write(handle, data, 0, 1);
				if (r < 0) {
					throw new IOException("Write error " + r);
				}
			}

			
			public synchronized void write(byte[] buf, int off, int len) throws IOException {
				if (handle == 0 || outputState == 2)
					throw new IOException("Closed");
				if (len+off > buf.length || off < 0 || len < 0)
					throw new IllegalArgumentException();
				int r;
//				if (off > 0) {
//					byte[] temp = new byte[len];
//					System.arraycopy(buf, off, temp, 0, len);
//					r = _write(handle, temp, 0, len);
//				} else {
				r = _write(handle, buf, off, len);
//				}
				if (r < 0) {
					throw new IOException("Write error " + r);
				}
			}
			
			public void close() {
				outputState = 2;
			}
		};
	}
	
	public void close() {
		if (connectState == 2 || handle == 0) return;
		connectState = 2;
		synchronized (globalLock) {
//			_closeSsl(handle);
			_closeConnection(handle);
		}
	}

	public DataInputStream openDataInputStream() throws IOException {
		return new DataInputStream(openInputStream());
	}

	public DataOutputStream openDataOutputStream() throws IOException {
		return new DataOutputStream(openOutputStream());
	}

	public String getAddress() throws IOException {
		return host;
	}

	public String getLocalAddress() throws IOException {
		return System.getProperty("microedition.hostname");
	}

	public int getLocalPort() throws IOException {
		// TODO
		return 0;
	}

	public int getPort() throws IOException {
		return port;
	}

	public int getSocketOption(byte arg0) throws IllegalArgumentException, IOException {
		// TODO
		return 0;
	}

	public void setSocketOption(byte arg0, int arg1) throws IllegalArgumentException, IOException {
		// TODO
	}

	public SecurityInfo getSecurityInfo() throws IOException {
		// TODO
		return null;
	}
	
	private Finalizer registerFinalize() {
		return new Finalizer() {
			public void finalizeImpl() {
				_finalize();
			}
		};
	}
	
	private void _finalize() {
		if (handle == 0) return;
		if (connectState == 1) {
			connectState = 2;
			_closeConnection(handle);
		}
		_destruct(handle);
		handle = 0;
	}

	private native int _new();
	private native int _set(int handle, String url, String host, int port);
	private native int _initSsl(int handle);
	private native int _connect(int handle);
	private native int _handshake(int handle);
	native int _read(int handle, byte[] data, int offset, int length);
	native int _write(int handle, byte[] data, int offset, int length);
	private native int _closeSsl(int handle);
	private native int _closeConnection(int handle);
	private native int _destruct(int handle);
	
	private static native int _initLibrary();
	static native int _freeLibrary();

}
