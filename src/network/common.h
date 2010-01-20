
#define NET_WANT_READ             NET_EVENT_READ
#define NET_WANT_WRITE            NET_EVENT_WRITE
#define NET_WANT_ACCEPT           NET_EVENT_READ
#define NET_WANT_SSL_READ         0x0010
#define NET_WANT_SSL_WRITE        0x0020
#define NET_WANT_SSL_ACCEPT       0x0040
#define NET_WANT_SSL_CONNECT      0x0080
#define NET_WANT_SSL_X509_LOOKUP  0x0100

#define NET_PROCESSING_BUSY       0x8000
#define NET_CLEANUP               0x4000
#define NET_INITIALIZED           0x2000
#define NET_TIMER_ENABLED         0x1000

#define NET_CON_STRUCT_BASIC \
	int                  sd;        /** socket descriptor */ \
	uint32_t             flags;     /** Connection flags */ \
	void*                ptr;       /** data pointer */ \
	net_connection_cb    callback;  /** Callback function */ \
	struct timeout_evt*  timeout;   /** timeout event handler */

#define NET_CON_STRUCT_SSL \
	SSL*                 ssl;       /** SSL handle */ \
	size_t               write_len; /** Length of last SSL_write(), only used if flags is NET_WANT_SSL_READ. */ \

#ifdef USE_SSL
#define NET_CON_STRUCT_COMMON \
	NET_CON_STRUCT_BASIC \
	NET_CON_STRUCT_SSL
#else
#define NET_CON_STRUCT_COMMON \
	NET_CON_STRUCT_BASIC
#endif

