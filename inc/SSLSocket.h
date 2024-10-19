#include <e32base.h>

#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <jni.h>

#define BUFFER_SIZE 1024

NONSHARABLE_CLASS(CSSLSocket) : public CBase
{
public:
	CSSLSocket();
	~CSSLSocket();
	
	void Set(const char* aName, const char* aHost, int aPort);
	TInt InitSsl();
	
	TInt Connect();
	TInt Handshake();
	
	TInt Read(JNIEnv* aEnv, jbyteArray aJavaArray, int aOffset, int aLen);
	TInt Write(const unsigned char* aData, int aLen);

	TInt CloseSsl();
	void CloseConnection();
	
private:
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;

#ifdef USE_MBEDTLS_NET
	mbedtls_net_context server_fd;
#else
public:
	TInt iSockDesc;
#endif
private:
	char *iName;
	char *iHost;
	int iPort;
	
	char *iBuffer;
	int iBufferPosition;
	int iBufferState;
	
};
