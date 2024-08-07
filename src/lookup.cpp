/*
 * Description: Automatically generated JNI lookup file. Do not modify manually.
 */

#include "javasymbianoslayer.h"
typedef void (*TFunc)();
#include "ru_nnproject_tls_SSLSocket.h"
const FuncTable funcTable[] = {
   { "Java_ru_nnproject_tls_SSLSocket__1closeConnection", (unsigned int) Java_ru_nnproject_tls_SSLSocket__1closeConnection},
   { "Java_ru_nnproject_tls_SSLSocket__1closeSsl", (unsigned int) Java_ru_nnproject_tls_SSLSocket__1closeSsl},
   { "Java_ru_nnproject_tls_SSLSocket__1connect", (unsigned int) Java_ru_nnproject_tls_SSLSocket__1connect},
   { "Java_ru_nnproject_tls_SSLSocket__1destruct", (unsigned int) Java_ru_nnproject_tls_SSLSocket__1destruct},
   { "Java_ru_nnproject_tls_SSLSocket__1freeLibrary", (unsigned int) Java_ru_nnproject_tls_SSLSocket__1freeLibrary},
   { "Java_ru_nnproject_tls_SSLSocket__1handshake", (unsigned int) Java_ru_nnproject_tls_SSLSocket__1handshake},
   { "Java_ru_nnproject_tls_SSLSocket__1initLibrary", (unsigned int) Java_ru_nnproject_tls_SSLSocket__1initLibrary},
   { "Java_ru_nnproject_tls_SSLSocket__1initSsl", (unsigned int) Java_ru_nnproject_tls_SSLSocket__1initSsl},
   { "Java_ru_nnproject_tls_SSLSocket__1new", (unsigned int) Java_ru_nnproject_tls_SSLSocket__1new},
   { "Java_ru_nnproject_tls_SSLSocket__1read", (unsigned int) Java_ru_nnproject_tls_SSLSocket__1read},
   { "Java_ru_nnproject_tls_SSLSocket__1set", (unsigned int) Java_ru_nnproject_tls_SSLSocket__1set},
   { "Java_ru_nnproject_tls_SSLSocket__1write", (unsigned int) Java_ru_nnproject_tls_SSLSocket__1write}
};

IMPORT_C TFunc jni_lookup(const char* name);
EXPORT_C TFunc jni_lookup(const char* name) {
    return (TFunc)findMethod(name, funcTable, sizeof(funcTable)/sizeof(FuncTable));
}
