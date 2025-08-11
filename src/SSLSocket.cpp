/**
 * Copyright (c) 2024 Arman Jussupgaliyev
 */

#include "ru_nnproject_tls_SSLSocket.h"
#include <jni.h>
#include "SSLSocket.h"
//#ifdef RD_JAVA_S60_RELEASE_9_2
//#include "jniarrayutils.h"
//#include "jutils.h"
//#endif
#ifdef RD_JAVA_S60_RELEASE_9_2
#include "logger.h"
#else
#define PLOG(component, str)
#define PLOG1(component, str, a)
#define PLOG2(component, str, a)
#define ELOG1(component, str, a)
#endif
//#include <mbedtls/debug.h>

//static bool psaInitState = false;

JNIEXPORT jint JNICALL Java_ru_nnproject_tls_SSLSocket__1new
 (JNIEnv* aEnv, jobject)
{
	CSSLSocket* s = new CSSLSocket();
	return reinterpret_cast<jint>(s);
}

JNIEXPORT jint JNICALL Java_ru_nnproject_tls_SSLSocket__1set
 (JNIEnv* aEnv, jobject, jint aHandle, jstring aUrl, jstring aHost, jint aPort)
{
	CSSLSocket* s = reinterpret_cast<CSSLSocket*>(aHandle);
//	const char* url = aEnv->GetStringUTFChars(aUrl, 0);
	const char* host = aEnv->GetStringUTFChars(aHost, 0);
	s->Set(NULL, host, aPort);
//	aEnv->ReleaseStringUTFChars(aUrl, url);
	aEnv->ReleaseStringUTFChars(aHost, host);
	
	return 0;
}

JNIEXPORT jint JNICALL Java_ru_nnproject_tls_SSLSocket__1initSsl
 (JNIEnv*, jobject, jint aHandle)
{
	CSSLSocket* s = reinterpret_cast<CSSLSocket*>(aHandle);
	TInt r = s->InitSsl();
	return r;
}

JNIEXPORT jint JNICALL Java_ru_nnproject_tls_SSLSocket__1connect
 (JNIEnv*, jobject, jint aHandle)
{
	CSSLSocket* s = reinterpret_cast<CSSLSocket*>(aHandle);
	TInt r = s->Connect();
	return r;
}

JNIEXPORT jint JNICALL Java_ru_nnproject_tls_SSLSocket__1handshake
 (JNIEnv*, jobject, jint aHandle)
{
	CSSLSocket* s = reinterpret_cast<CSSLSocket*>(aHandle);
	TInt r = s->Handshake();
	return r;
}

JNIEXPORT jint JNICALL Java_ru_nnproject_tls_SSLSocket__1verify
 (JNIEnv*, jobject, jint aHandle)
{
	CSSLSocket* s = reinterpret_cast<CSSLSocket*>(aHandle);
	TInt r = s->Verify();
	return r;
}

JNIEXPORT jint JNICALL Java_ru_nnproject_tls_SSLSocket__1localPort
 (JNIEnv*, jobject, jint aHandle)
{
	CSSLSocket* s = reinterpret_cast<CSSLSocket*>(aHandle);
	TInt r = s->LocalPort();
	return r;
}

JNIEXPORT jint JNICALL Java_ru_nnproject_tls_SSLSocket__1read
 (JNIEnv* aEnv, jobject, jint aHandle, jbyteArray aData, jint aOffset, jint aLen)
{
	CSSLSocket* s = reinterpret_cast<CSSLSocket*>(aHandle);
	TInt r = s->Read(aEnv, aData, aOffset, aLen);
	return r;
}

JNIEXPORT jint JNICALL Java_ru_nnproject_tls_SSLSocket__1write
 (JNIEnv* aEnv, jobject, jint aHandle, jbyteArray aData, jint aOffset, jint aLen)
{
	CSSLSocket* s = reinterpret_cast<CSSLSocket*>(aHandle);
	signed char *data = (signed char*) new char[aLen];
//#ifdef RD_JAVA_S60_RELEASE_9_2
//	JNIArrayUtils::CopyToNative(*aEnv, aData, aOffset, aLen, data);
//#else
	aEnv->GetByteArrayRegion(aData, aOffset, aLen, data);
//#endif
	
	TInt r = s->Write((unsigned char*) data, aLen);
	
	delete[] data;
	data = NULL;
	
	return r;
}

JNIEXPORT jint JNICALL Java_ru_nnproject_tls_SSLSocket__1closeSsl
 (JNIEnv*, jobject, jint aHandle)
{
	CSSLSocket* s = reinterpret_cast<CSSLSocket*>(aHandle);
	TInt r = s->CloseSsl();
	return r;
}

JNIEXPORT jint JNICALL Java_ru_nnproject_tls_SSLSocket__1closeConnection
 (JNIEnv*, jobject, jint aHandle)
{
	CSSLSocket* s = reinterpret_cast<CSSLSocket*>(aHandle);
	s->CloseConnection();
	return 0;
}

JNIEXPORT jint JNICALL Java_ru_nnproject_tls_SSLSocket__1destruct
 (JNIEnv*, jobject, jint aHandle)
{
	CSSLSocket* s = reinterpret_cast<CSSLSocket*>(aHandle);
	delete s;
	return 0;
}

JNIEXPORT jint JNICALL Java_ru_nnproject_tls_SSLSocket__1initLibrary
 (JNIEnv*, jclass)
{
#if defined(MBEDTLS_USE_PSA_CRYPTO)
//	if (!psaInitState) {
//		psaInitState = true;
		psa_status_t status = psa_crypto_init();
		if (status != PSA_SUCCESS) {
			ELOG1(EJavaRuntime, "PSA init error: %x", -((int) status));
		}
//	}
#endif
	
//#if defined(MBEDTLS_DEBUG_C)
//    mbedtls_debug_set_threshold(1);
//#endif
	return 0;
}

JNIEXPORT jint JNICALL Java_ru_nnproject_tls_SSLSocket__1freeLibrary
 (JNIEnv*, jclass)
{
#if defined(MBEDTLS_USE_PSA_CRYPTO)
//	if (psaInitState) {
		mbedtls_psa_crypto_free();
//	}
#endif
	return 0;
}


