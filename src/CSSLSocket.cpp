#include "SSLSocket.h"
#include <stdio.h>
#include <stdlib.h>
#ifndef USE_MBEDTLS_NET
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <wchar.h>
#include <errno.h>
#endif
#ifdef RD_JAVA_S60_RELEASE_9_2
#include "logger.h"
#else
#define PLOG(component, str)
#define PLOG1(component, str, a)
#define PLOG2(component, str, a)
#define ELOG1(component, str, a)
#endif


CSSLSocket::CSSLSocket()
{
//	PLOG(EJavaRuntime, "+CSSLSocket::CSSLSocket()");
#ifdef USE_MBEDTLS_NET
	mbedtls_net_init(&server_fd);
#endif

	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
//	PLOG(EJavaRuntime, "-CSSLSocket::CSSLSocket()");
}

CSSLSocket::~CSSLSocket()
{
//	PLOG(EJavaRuntime, "+CSSLSocket::~CSSLSocket()");
#ifdef USE_MBEDTLS_NET
	mbedtls_net_free(&server_fd);
#else
	if (iSockDesc != NULL) {
		close(iSockDesc);
		iSockDesc = NULL;
	}
#endif
	
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

//	if (iName != NULL) {
//		delete[] iName;
//	}
	if (iHost != NULL) {
		delete[] iHost;
	}
//	PLOG(EJavaRuntime, "-CSSLSocket::~CSSLSocket()");
}

#ifndef USE_MBEDTLS_NET
static int send_callback(void *ctx, const unsigned char *buf, size_t len)
{
	CSSLSocket* s = (CSSLSocket*) ctx;
	int r = send(s->iSockDesc, buf, len, 0);
	if (r < 0)
		ELOG1(EJavaRuntime, "CSSLSocket::send_callback(): Socket send error: %d", errno);
	return r;
}

static int recv_callback(void *ctx, unsigned char *buf, size_t len)
{
	CSSLSocket* s = (CSSLSocket*) ctx;
	int r = recv(s->iSockDesc, buf, len, 0);
	if (r < 0)
		ELOG1(EJavaRuntime, "CSSLSocket::recv_callback(): Socket recv error: %d", errno);
	if (r == -1 && errno == EAGAIN) return 0;
	return r;
}
#endif

//static void my_debug(void *ctx, int level,
//                     const char *file, int line,
//                     const char *str)
//{
////	((void) level);
//	PLOG3(EJavaRuntime, "mbedtls: %s:%04d: %s", file, line, str);
//}

TInt CSSLSocket::InitSsl()
{
//	PLOG(EJavaRuntime, "+CSSLSocket::InitSsl()");

	TInt ret(0);
	
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
									 NULL, 0)) != 0) {
		ELOG1(EJavaRuntime, "CSSLSocket::InitSsl(): Seed error: %x", -ret);
		goto exit;
	}

	if ((ret = mbedtls_ssl_config_defaults(&conf,
											   MBEDTLS_SSL_IS_CLIENT,
											   MBEDTLS_SSL_TRANSPORT_STREAM,
											   MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		ELOG1(EJavaRuntime, "CSSLSocket::InitSsl(): Config error: %x", -ret);
		goto exit;
	}
	
	
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
//	mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);
	
	if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
		ELOG1(EJavaRuntime, "CSSLSocket::InitSsl(): Setup error: %x", -ret);
		goto exit;
	}
#ifdef USE_MBEDTLS_NET
	mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
#else
	mbedtls_ssl_set_bio(&ssl, this, send_callback, recv_callback, NULL);
#endif
	
	exit:
//	PLOG(EJavaRuntime, "-CSSLSocket::InitSsl()");
	return ret;
}

TInt CSSLSocket::CloseSsl()
{
//	PLOG(EJavaRuntime, "CSSLSocket::CloseSsl()");
	return mbedtls_ssl_close_notify(&ssl);
}

void CSSLSocket::CloseConnection()
{
//	PLOG(EJavaRuntime, "CSSLSocket::CloseConnection()");
#ifdef USE_MBEDTLS_NET
	mbedtls_net_close(&server_fd);
#else
	if (iSockDesc != NULL) {
		close(iSockDesc);
		iSockDesc = NULL;
	}
#endif
}

void CSSLSocket::Set(const char* aName, const char* aHost, int aPort)
{
//	PLOG(EJavaRuntime, "CSSLSocket::Set()");
//	iName = new char[strlen(aName)+1];
//	strcpy(iName, aName);
	iHost = new char[strlen(aHost)+1];
	strcpy(iHost, aHost);
	iPort = aPort;
}

#ifdef USE_MBEDTLS_NET
void reverse(char s[])
{
	int i, j;
	char c;
	
	for (i = 0, j = strlen(s)-1; i<j; i++, j--) {
		c = s[i];
		s[i] = s[j];
		s[j] = c;
	}
}

void itoa(int n, char s[])
{
	int i, sign;
	
	if ((sign = n) < 0)  /* record sign */
		n = -n;          /* make n positive */
	i = 0;
	do {       /* generate digits in reverse order */
		s[i++] = n % 10 + '0';   /* get next digit */
	} while ((n /= 10) > 0);     /* delete it */
	if (sign < 0)
		s[i++] = '-';
	s[i] = '\0';
	reverse(s);
}
#endif

TInt CSSLSocket::Connect()
{
//	PLOG(EJavaRuntime, "+CSSLSocket::Connect()");
#ifdef USE_MBEDTLS_NET
	char *port = new char[8];
	itoa(iPort, port);
//	PLOG2(EJavaRuntime, "CSSLSocket::Connect(): host=%s, port=%s", iHost, port);
	
	TInt ret(0);
	if ((ret = mbedtls_net_connect(&server_fd, iHost, port, MBEDTLS_NET_PROTO_TCP)) != 0) {
		ELOG1(EJavaRuntime, "CSSLSocket::Connect(): Connect error: %x", -ret);
		return ret;
	}
#else
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(iPort);
	
	iSockDesc = socket(AF_INET, SOCK_STREAM, 0);
	if (iSockDesc < 0) {
		return -3;
	}
	if (!inet_aton(iHost, &addr.sin_addr)) {
		struct hostent* hp = gethostbyname(iHost);
		if (hp == NULL) {
			return -1;
		}
		addr.sin_addr.s_addr = ((struct in_addr*)(hp->h_addr))->s_addr;
	}
	
	int rc = connect(iSockDesc, (struct sockaddr*)&addr, sizeof(addr));
	if (rc < 0) {
		ELOG1(EJavaRuntime, "CSSLSocket::Connect(): Connect error: %d", rc);
		return -2;
	}
#endif
//	PLOG(EJavaRuntime, "-CSSLSocket::Connect()");
	return 0;
}

TInt CSSLSocket::Handshake()
{ 
//	PLOG(EJavaRuntime, "+CSSLSocket::Handshake()");
	int ret(0);

	if ((ret = mbedtls_ssl_set_hostname(&ssl, (const char*) iHost)) != 0) {
		ELOG1(EJavaRuntime, "CSSLSocket::Handshake(): set hostname error: %x", -ret);
		goto exit;
	}
	
	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
			ret == MBEDTLS_ERR_SSL_WANT_WRITE/* ||
			ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
			ret == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS*/) {
			continue;
		}
		
		if (ret < 0) {
			ELOG1(EJavaRuntime, "CSSLSocket::Handshake(): handshake error: %x", -ret);
		}
			
		break;
	}
	
	exit:
//	PLOG(EJavaRuntime, "-CSSLSocket::Handshake()");
	return ret;
}

TInt CSSLSocket::Read(unsigned char* aData, int aLen)
{
	int r;
	do {
		memset(aData, 0, sizeof(aData));
		r = mbedtls_ssl_read(&ssl, (unsigned char*) aData, static_cast<unsigned int>(aLen));
		
		if (r == MBEDTLS_ERR_SSL_WANT_READ ||
			r == MBEDTLS_ERR_SSL_WANT_WRITE/* ||
			r == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
			r == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS*/) {
//			PLOG(EJavaRuntime, "CSSLSocket::Read(): repeat requested");
			continue;
		}
		if (r == MBEDTLS_ERR_SSL_CLIENT_RECONNECT) {
			r = Handshake();
			if (r < 0) {
				ELOG1(EJavaRuntime, "CSSLSocket::Read(): reconnect handshake error: %x", -r);
				break;
			}
			continue;
		}
		if (r < 0) {
			ELOG1(EJavaRuntime, "CSSLSocket::Read(): ssl read error: %x", -r);
			break;
		}
//		PLOG1(EJavaRuntime, "CSSLSocket::Read(): read bytes: %d", r);
//		if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
//			break;
//		}
		break;
	} while (1);
	return r;
}

TInt CSSLSocket::Write(const unsigned char* aData, int aLen)
{
	int r;
	while ((r = mbedtls_ssl_write(&ssl, (const unsigned char*) aData, static_cast<unsigned int>(aLen))) <= 0) {
		if (r == MBEDTLS_ERR_SSL_WANT_READ ||
			r == MBEDTLS_ERR_SSL_WANT_WRITE/* ||
			r == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
			r == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS*/) {
//			PLOG(EJavaRuntime, "CSSLSocket::Write(): repeat requested");
			continue;
		}
		if (r < 0) {
			ELOG1(EJavaRuntime, "CSSLSocket::Write(): ssl write error: %x", -r);
			break;
		}
//		PLOG1(EJavaRuntime, "CSSLSocket::Write(): wrote bytes: %d", r);
		break;
	}
	return r;
}
