package ru.nnproject.tls;

import com.nokia.mj.impl.rt.support.Finalizer;

class LibraryFinalizer {

	Finalizer finalizer;
	
	LibraryFinalizer() {
		finalizer = registerFinalize();
	}
	
	Finalizer registerFinalize() {
		return new Finalizer() {
			public void finalizeImpl() {
				SSLSocket._freeLibrary();
			}
		};
	}
}
