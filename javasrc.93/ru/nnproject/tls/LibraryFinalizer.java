package ru.nnproject.tls;

import com.nokia.mj.impl.vmport.Finalizer;

class LibraryFinalizer {

	Finalizer finalizer;
	
	LibraryFinalizer() {
		finalizer = registerFinalize();
	}
	
	Finalizer registerFinalize() {
		return new Finalizer() {
			public void finalize() {
				super.finalize();
				SSLSocket._freeLibrary();
			}
		};
	}
}
