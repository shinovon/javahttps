package ru.nnproject.tls;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;

import javax.microedition.io.StreamConnection;

import com.nokia.mj.impl.vmport.Finalizer;
import com.nokia.mj.impl.vmport.VmPort;

public class SSLSocket implements StreamConnection {

	private static LibraryFinalizer libraryFinalizer;
	
	static {
		try {
			VmPort.getInstance().System_loadLibrary("javannssl");
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
	
	public SSLSocket(String host, int port) throws IOException {
		finalizer = registerFinalize();
		System.out.println("creating");
		handle = _new();
		System.out.println("created");
		int r = _set(handle, "", host, port);
		if (r != 0) {
			throw new IOException("Set host failed: " + r);
		}
		System.out.println("set");
		r = _initSsl(handle);
		if (r != 0) {
			throw new IOException("Init ssl failed: " + r);
		}
		System.out.println("inited");
	}
	
	public SSLSocket(String url) throws IOException {
		throw new IOException("Not supported");
	}
	
	public void connect() throws IOException{
		if (connectState != 0) return;
		connectState = 1;
		System.out.println("connecting");
		long l = System.currentTimeMillis();
		int r = _connect(handle);
		if (r != 0)
			throw new IOException("Connect error " + r);
		System.out.println("connected in " + (System.currentTimeMillis()-l));

		l = System.currentTimeMillis();
		r = _handshake(handle);
		if (r != 0)
			throw new IOException("Handshake error " + r);
		System.out.println("handshaked in " + (System.currentTimeMillis()-l));
	}
	
	public InputStream openInputStream() throws IOException {
		if (connectState == 0)
			connect();
		if (inputState != 0)
			throw new IOException("Input already open");
		inputState = 1;
		return new InputStream() {

			public int read() throws IOException {
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
			
			public int read(byte[] buf, int off, int len) throws IOException {
				if (handle == 0 || inputState == 2)
					throw new IOException("Closed");
				if (len+off > buf.length || off < 0 || len < 0)
					throw new IllegalArgumentException();
				int r;
				if (off > 0) {
					byte[] temp = new byte[len];
					r = _read(handle, temp, 0, len);
					System.arraycopy(temp, 0, buf, 0, r);
				} else {
					r = _read(handle, buf, off, len);
				}
				if (r == 0) return -1;
				if (r < 0) {
					throw new IOException("Read error " + r);
				}
				try {
					Thread.sleep(1);
				} catch (InterruptedException e) {
					throw new InterruptedIOException(e.toString());
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

			public void write(int b) throws IOException {
				if (handle == 0 || outputState == 2)
					throw new IOException("Closed");
				byte[] data = new byte[1];
				int r = _write(handle, data, 0, 1);
				if (r < 0) {
					throw new IOException("Write error " + r);
				}
			}

			
			public void write(byte[] buf, int off, int len) throws IOException {
				if (handle == 0 || outputState == 2)
					throw new IOException("Closed");
				if (len+off > buf.length || off < 0 || len < 0)
					throw new IllegalArgumentException();
				int r;
				if (off > 0) {
					byte[] temp = new byte[len];
					System.arraycopy(buf, off, temp, 0, len);
					r = _write(handle, temp, 0, len);
				} else {
					r = _write(handle, buf, off, len);
				}
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
		_closeSsl(handle);
		_closeConnection(handle);
		_destruct(handle);
		handle = 0;
	}

	public DataInputStream openDataInputStream() throws IOException {
		return new DataInputStream(openInputStream());
	}

	public DataOutputStream openDataOutputStream() throws IOException {
		return new DataOutputStream(openOutputStream());
	}
	
	private Finalizer registerFinalize() {
		return new Finalizer() {
			public void finalize() {
				super.finalize();
				_finalize();
			}
		};
	}
	
	private void _finalize() {
		if (handle == 0) return;
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
