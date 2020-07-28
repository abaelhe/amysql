/* Copyright (C) 2012 Abael Heyijun <hyjdyx@gmail.com>
	free for non-commercial use, All rights reserved. */


#ifndef __UMY_H__
#define __UMY_H__
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <alloca.h>

//////// Python
#include <Python.h>
#include <modsupport.h>
#include <time.h>
#include <timefuncs.h>
#include <datetime.h>
#include <structmember.h>

//////// System - Level
#define true                                1
#define false                               0
#define LOCK(con)              con->rwlock =1
#define UNLOCK(con)            con->rwlock =0
#ifdef Py_PYTHON_H
#define THROW(...) do{fprintf(stderr,"Exception call: %s (%s:%ld)\n",__FUNCTION__, __FILE__, (long)__LINE__);fprintf(stderr,  __VA_ARGS__);fflush(stderr);exit(-1);}while(0)
#define MyMalloc(ptr, size)    if((ptr=PyMem_Malloc(size))==NULL){THROW("Exception memory alloction(size:%d) ",(size));}
#define MyCalloc(ptr, n, size) if((ptr=PyMem_Malloc((n) *(size)))==NULL){THROW("Exception memory alloction(size:%d) ",(size));}
#define MyRealloc(ptr, size)   if((ptr=PyMem_Realloc((void *)(ptr),size))==NULL){THROW("Exception memory alloction(size:%d) ",(size));}
#define MyFree(p)        if(p)PyMem_Free(p)
#else
#define THROW(...) do{fprintf(stderr,"Exception call: %s (%s:%ld)\n",__FUNCTION__, __FILE__, (long)__LINE__);fprintf(stderr,  __VA_ARGS__);fflush(stderr);exit(-1);}while(0)
#define MyMalloc(ptr, size)  if((ptr=malloc(size)==NULL){THROW("Exception memory alloction(size:%d) ",(size));}
#define MyCalloc(ptr, n, size)  if((ptr=calloc(n, (size)))==NULL){THROW("Exception memory alloction(size:%d) ",(size));}
#define MyRealloc(ptr, size)  if((ptr=realloc((void *)(ptr), (size)))==NULL){THROW("Exception memory alloction(size:%d) ",(size));}
#define MyFree(p)        if(p)free(p)
#endif
#define EXPORTFUNCTION extern "C" __declspec(dllexport)
typedef u_int8_t                        UINT1;
typedef u_int16_t                       UINT2;
typedef u_int32_t                       UINT4;
typedef u_int64_t                       UINT8;

typedef int8_t                           INT1;
typedef int16_t                          INT2;
typedef int32_t                          INT4;
typedef int64_t                          INT8;
typedef unsigned long long        ulonglong;
typedef unsigned long                 ulong;
typedef unsigned char                  bool;


//////// App Level
#define MY_BUFFER_MAX              1073741824 // (1024*1024*1024)
#define MY_PACKET_MAX                16777215 // (1024*1024*16 -1)
#define MY_HANDSHAKE_SIZE                  74
#define MY_HEADER_SIZE                      4
#define MY_SQLSTATE_LENGTH                  5
#define MY_PROTOCOL_VERSION               0xa
#define MY_SHA1_HASH_SIZE                  20
#define MY_NULL_LENGTH ((unsigned long) ~0)
#define MY_SCRAMBLE_LENGTH                 20
#define MY_SCRAMBLE_LENGTH_323              8
#define MY_PACKET_ERROR                        0
#define MY_TX_BUFFER_SIZE             4194304 //(1024*1024*4)
#define MY_BUFFER_SIZE               16777216 // (1024*1024*16)
#define MY_PACKET_MAX                16777215 // (1024*1024*16 -1)
#define SERVER_STATUS_IN_TRANS              1
#define SERVER_STATUS_AUTOCOMMIT            2    /* Server in auto_commit mode */
#define SERVER_MORE_RESULTS_EXISTS          8    /* Multi query - next query exists */
#define SERVER_QUERY_NO_GOOD_INDEX_USED    16
#define SERVER_QUERY_NO_INDEX_USED         32
#define PVERSION41_CHAR '*'

#define SHA1CircularShift(bits,word)  (((word) << (bits)) | ((word) >> (32-(bits))))
enum sha_result_codes {
	SHA_SUCCESS = 0, SHA_NULL, /* Null pointer parameter */
	SHA_INPUT_TOO_LONG, /* input data too long */
	SHA_STATE_ERROR /* called Input after Result */
};
typedef struct SHA1_CONTEXT {
	ulonglong Length; /* Message length in bits      */
	UINT4 Intermediate_Hash[MY_SHA1_HASH_SIZE / 4]; /* Message Digest  */
	int Computed; /* Is the digest computed?	   */
	int Corrupted; /* Is the message digest corrupted? */
	INT2 Message_Block_Index; /* Index into message block array   */
	UINT1 Message_Block[64]; /* 512-bit message blocks      */
} SHA1_CONTEXT;
static const UINT4 sha_const_key[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,0xC3D2E1F0 };
static const UINT4 SHA1_KEY[] = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };

static PyObject *sockmodule = NULL;
static PyObject *sockclass = NULL;
static PyTypeObject ConType;
static PyObject *amysql_Error;
static PyObject *amysql_SQLError;

enum MY_CHARSETS {
	MCS_UNDEFINED = 0,
	MCS_big5_chinese_ci = 1,
	MCS_big5_bin = 84,
	MCS_dec8_swedish_ci = 3,
	MCS_dec8_bin = 69,
	MCS_cp850_general_ci = 4,
	MCS_cp850_bin = 80,
	MCS_hp8_english_ci = 6,
	MCS_hp8_bin = 72,
	MCS_koi8r_general_ci = 7,
	MCS_koi8r_bin = 74,
	MCS_latin1_german1_ci = 5,
	MCS_latin1_swedish_ci = 8,
	MCS_latin1_danish_ci = 15,
	MCS_latin1_german2_ci = 31,
	MCS_latin1_bin = 47,
	MCS_latin1_general_ci = 48,
	MCS_latin1_general_cs = 49,
	MCS_latin1_spanish_ci = 94,
	MCS_latin2_czech_cs = 2,
	MCS_latin2_general_ci = 9,
	MCS_latin2_hungarian_ci = 21,
	MCS_latin2_croatian_ci = 27,
	MCS_latin2_bin = 77,
	MCS_swe7_swedish_ci = 10,
	MCS_swe7_bin = 82,
	MCS_ascii_general_ci = 11,
	MCS_ascii_bin = 65,
	MCS_ujis_japanese_ci = 12,
	MCS_ujis_bin = 91,
	MCS_sjis_japanese_ci = 13,
	MCS_sjis_bin = 88,
	MCS_hebrew_general_ci = 16,
	MCS_hebrew_bin = 71,
	MCS_tis620_thai_ci = 18,
	MCS_tis620_bin = 89,
	MCS_euckr_korean_ci = 19,
	MCS_euckr_bin = 85,
	MCS_koi8u_general_ci = 22,
	MCS_koi8u_bin = 75,
	MCS_gb2312_chinese_ci = 24,
	MCS_gb2312_bin = 86,
	MCS_greek_general_ci = 25,
	MCS_greek_bin = 70,
	MCS_cp1250_general_ci = 26,
	MCS_cp1250_czech_cs = 34,
	MCS_cp1250_croatian_ci = 44,
	MCS_cp1250_bin = 66,
	MCS_cp1250_polish_ci = 99,
	MCS_gbk_chinese_ci = 28,
	MCS_gbk_bin = 87,
	MCS_latin5_turkish_ci = 30,
	MCS_latin5_bin = 78,
	MCS_armscii8_general_ci = 32,
	MCS_armscii8_bin = 64,
	MCS_utf8_general_ci = 33,
	MCS_utf8_bin = 83,
	MCS_utf8_unicode_ci = 192,
	MCS_utf8_icelandic_ci = 193,
	MCS_utf8_latvian_ci = 194,
	MCS_utf8_romanian_ci = 195,
	MCS_utf8_slovenian_ci = 196,
	MCS_utf8_polish_ci = 197,
	MCS_utf8_estonian_ci = 198,
	MCS_utf8_spanish_ci = 199,
	MCS_utf8_swedish_ci = 200,
	MCS_utf8_turkish_ci = 201,
	MCS_utf8_czech_ci = 202,
	MCS_utf8_danish_ci = 203,
	MCS_utf8_lithuanian_ci = 204,
	MCS_utf8_slovak_ci = 205,
	MCS_utf8_spanish2_ci = 206,
	MCS_utf8_roman_ci = 207,
	MCS_utf8_persian_ci = 208,
	MCS_utf8_esperanto_ci = 209,
	MCS_utf8_hungarian_ci = 210,
	MCS_utf8_sinhala_ci = 211,
	MCS_ucs2_general_ci = 35,
	MCS_ucs2_bin = 90,
	MCS_ucs2_unicode_ci = 128,
	MCS_ucs2_icelandic_ci = 129,
	MCS_ucs2_latvian_ci = 130,
	MCS_ucs2_romanian_ci = 131,
	MCS_ucs2_slovenian_ci = 132,
	MCS_ucs2_polish_ci = 133,
	MCS_ucs2_estonian_ci = 134,
	MCS_ucs2_spanish_ci = 135,
	MCS_ucs2_swedish_ci = 136,
	MCS_ucs2_turkish_ci = 137,
	MCS_ucs2_czech_ci = 138,
	MCS_ucs2_danish_ci = 139,
	MCS_ucs2_lithuanian_ci = 140,
	MCS_ucs2_slovak_ci = 141,
	MCS_ucs2_spanish2_ci = 142,
	MCS_ucs2_roman_ci = 143,
	MCS_ucs2_persian_ci = 144,
	MCS_ucs2_esperanto_ci = 145,
	MCS_ucs2_hungarian_ci = 146,
	MCS_ucs2_sinhala_ci = 147,
	MCS_cp866_general_ci = 36,
	MCS_cp866_bin = 68,
	MCS_keybcs2_general_ci = 37,
	MCS_keybcs2_bin = 73,
	MCS_macce_general_ci = 38,
	MCS_macce_bin = 43,
	MCS_macroman_general_ci = 39,
	MCS_macroman_bin = 53,
	MCS_cp852_general_ci = 40,
	MCS_cp852_bin = 81,
	MCS_latin7_estonian_cs = 20,
	MCS_latin7_general_ci = 41,
	MCS_latin7_general_cs = 42,
	MCS_latin7_bin = 79,
	MCS_utf8mb4_general_ci = 45,
	MCS_utf8mb4_bin = 46,
	MCS_utf8mb4_unicode_ci = 224,
	MCS_utf8mb4_icelandic_ci = 225,
	MCS_utf8mb4_latvian_ci = 226,
	MCS_utf8mb4_romanian_ci = 227,
	MCS_utf8mb4_slovenian_ci = 228,
	MCS_utf8mb4_polish_ci = 229,
	MCS_utf8mb4_estonian_ci = 230,
	MCS_utf8mb4_spanish_ci = 231,
	MCS_utf8mb4_swedish_ci = 232,
	MCS_utf8mb4_turkish_ci = 233,
	MCS_utf8mb4_czech_ci = 234,
	MCS_utf8mb4_danish_ci = 235,
	MCS_utf8mb4_lithuanian_ci = 236,
	MCS_utf8mb4_slovak_ci = 237,
	MCS_utf8mb4_spanish2_ci = 238,
	MCS_utf8mb4_roman_ci = 239,
	MCS_utf8mb4_persian_ci = 240,
	MCS_utf8mb4_esperanto_ci = 241,
	MCS_utf8mb4_hungarian_ci = 242,
	MCS_utf8mb4_sinhala_ci = 243,
	MCS_cp1251_bulgarian_ci = 14,
	MCS_cp1251_ukrainian_ci = 23,
	MCS_cp1251_bin = 50,
	MCS_cp1251_general_ci = 51,
	MCS_cp1251_general_cs = 52,
	MCS_utf16_general_ci = 54,
	MCS_utf16_bin = 55,
	MCS_utf16_unicode_ci = 101,
	MCS_utf16_icelandic_ci = 102,
	MCS_utf16_latvian_ci = 103,
	MCS_utf16_romanian_ci = 104,
	MCS_utf16_slovenian_ci = 105,
	MCS_utf16_polish_ci = 106,
	MCS_utf16_estonian_ci = 107,
	MCS_utf16_spanish_ci = 108,
	MCS_utf16_swedish_ci = 109,
	MCS_utf16_turkish_ci = 110,
	MCS_utf16_czech_ci = 111,
	MCS_utf16_danish_ci = 112,
	MCS_utf16_lithuanian_ci = 113,
	MCS_utf16_slovak_ci = 114,
	MCS_utf16_spanish2_ci = 115,
	MCS_utf16_roman_ci = 116,
	MCS_utf16_persian_ci = 117,
	MCS_utf16_esperanto_ci = 118,
	MCS_utf16_hungarian_ci = 119,
	MCS_utf16_sinhala_ci = 120,
	MCS_cp1256_general_ci = 57,
	MCS_cp1256_bin = 67,
	MCS_cp1257_lithuanian_ci = 29,
	MCS_cp1257_bin = 58,
	MCS_cp1257_general_ci = 59,
	MCS_utf32_general_ci = 60,
	MCS_utf32_bin = 61,
	MCS_utf32_unicode_ci = 160,
	MCS_utf32_icelandic_ci = 161,
	MCS_utf32_latvian_ci = 162,
	MCS_utf32_romanian_ci = 163,
	MCS_utf32_slovenian_ci = 164,
	MCS_utf32_polish_ci = 165,
	MCS_utf32_estonian_ci = 166,
	MCS_utf32_spanish_ci = 167,
	MCS_utf32_swedish_ci = 168,
	MCS_utf32_turkish_ci = 169,
	MCS_utf32_czech_ci = 170,
	MCS_utf32_danish_ci = 171,
	MCS_utf32_lithuanian_ci = 172,
	MCS_utf32_slovak_ci = 173,
	MCS_utf32_spanish2_ci = 174,
	MCS_utf32_roman_ci = 175,
	MCS_utf32_persian_ci = 176,
	MCS_utf32_esperanto_ci = 177,
	MCS_utf32_hungarian_ci = 178,
	MCS_utf32_sinhala_ci = 179,
	MCS_binary = 63,
	MCS_geostd8_general_ci = 92,
	MCS_geostd8_bin = 93,
	MCS_cp932_japanese_ci = 95,
	MCS_cp932_bin = 96,
	MCS_eucjpms_japanese_ci = 97,
	MCS_eucjpms_bin = 98,
};

enum MY_CMD {
	COM_SLEEP,
	COM_QUIT,
	COM_INIT_DB,
	COM_QUERY,
	COM_FIELD_LIST,
	COM_CREATE_DB,
	COM_DROP_DB,
	COM_REFRESH,
	COM_SHUTDOWN,
	COM_STATISTICS,
	COM_PROCESS_INFO,
	COM_CONNECT,
	COM_PROCESS_KILL,
	COM_DEBUG,
	COM_PING,
	COM_TIME,
	COM_DELAYED_INSERT,
	COM_CHANGE_USER,
	COM_BINLOG_DUMP,
	COM_TABLE_DUMP,
	COM_CONNECT_OUT,
	COM_REGISTER_SLAVE,
	COM_STMT_PREPARE,
	COM_STMT_EXECUTE,
	COM_STMT_SEND_LONG_DATA,
	COM_STMT_CLOSE,
	COM_STMT_RESET,
	COM_SET_OPTION,
	COM_STMT_FETCH,
	COM_DAEMON,
	COM_END
};

enum MY_FIELDFLAG {
	MFFLAG_NOT_NULL_FLAG = 0x0001,
	MFFLAG_PRI_KEY_FLAG = 0x0002,
	MFFLAG_UNIQUE_KEY_FLAG = 0x0004,
	MFFLAG_MULTIPLE_KEY_FLAG = 0x0008,
	MFFLAG_BLOB_FLAG = 0x0010,
	MFFLAG_UNSIGNED_FLAG = 0x0020,
	MFFLAG_ZEROFILL_FLAG = 0x0040,
	MFFLAG_BINARY_FLAG = 0x0080,
	MFFLAG_ENUM_FLAG = 0x0100,
	MFFLAG_AUTO_INCREMENT_FLAG = 0x0200,
	MFFLAG_TIMESTAMP_FLAG = 0x0400,
	MFFLAG_SET_FLAG = 0x0800,
};

enum MY_STATUS {
	MY_STATUS_READY, MY_STATUS_GET_RESULT, MY_STATUS_USE_RESULT
};

enum MY_PACKETREAD {
	MPR_NONE = 0,
	MPR_MORE = 1,
	MPR_ERROR = 2,
	MPR_TRUE = 4,
	MPR_START = 8,
	MPR_END = 16,
	MPR_EOF = 32,
};

enum MY_FIELDTYPE {
	MFTYPE_DECIMAL = 0x00,
	MFTYPE_TINY = 0x01,
	MFTYPE_SHORT = 0x02,
	MFTYPE_LONG = 0x03,
	MFTYPE_FLOAT = 0x04,
	MFTYPE_DOUBLE = 0x05,
	MFTYPE_NULL = 0x06,
	MFTYPE_TIMESTAMP = 0x07,
	MFTYPE_LONGLONG = 0x08,
	MFTYPE_INT24 = 0x09,
	MFTYPE_DATE = 0x0a,
	MFTYPE_TIME = 0x0b,
	MFTYPE_DATETIME = 0x0c,
	MFTYPE_YEAR = 0x0d,
	MFTYPE_NEWDATE = 0x0e,
	MFTYPE_VARCHAR = 0x0f,
	MFTYPE_BIT = 0x10,
	MFTYPE_NEWDECIMAL = 0xf6,
	MFTYPE_ENUM = 0xf7,
	MFTYPE_SET = 0xf8,
	MFTYPE_TINY_BLOB = 0xf9,
	MFTYPE_MEDIUM_BLOB = 0xfa,
	MFTYPE_LONG_BLOB = 0xfb,
	MFTYPE_BLOB = 0xfc,
	MFTYPE_VAR_STRING = 0xfd,
	MFTYPE_STRING = 0xfe,
	MFTYPE_GEOMETRY = 0xff,
};

enum MY_CAPABILITIES {
	MCP_LONG_PASSWORD = (1 << 0), // new more secure passwords
	MCP_FOUND_ROWS = (1 << 1), //Found instead of affected rows
	MCP_LONG_FLAG = (1 << 2), //Get all column flags */
	MCP_CONNECT_WITH_DB = (1 << 3), // One can specify db on connect */
	MCP_NO_SCHEMA = (1 << 4), //  /* Don't allow database.table.column */
	MCP_COMPRESS = (1 << 5), // Can use compression protocol */
	MCP_ODBC = (1 << 6), // Odbc client */
	MCP_LOCAL_FILES = (1 << 7), // Can use LOAD DATA LOCAL */
	MCP_IGNORE_SPACE = (1 << 8), // Ignore spaces before '(' */
	MCP_PROTOCOL_41 = (1 << 9), // New 4.1 protocol */
	MCP_INTERACTIVE = (1 << 10), // This is an interactive client */
	MCP_SSL = (1 << 11), //Switch to SSL after handshake */
	MCP_IGNORE_SIGPIPE = (1 << 12), // IGNORE sigpipes */
	MCP_TRANSACTIONS = (1 << 13), // Client knows about transactions */
	MCP_RESERVED = (1 << 14), // Old flag for 4.1 protocol  */
	MCP_SECURE_CONNECTION = (1 << 15), // New 4.1 authentication */
	MCP_MULTI_STATEMENTS = (1 << 16), // Enable/disable multi-stmt support */
	MCP_MULTI_RESULTS = (1 << 17), // Enable/disable multi-results */
};

typedef struct Field {
	PyObject *name;
	UINT1 type;
	UINT2 flags;
	UINT2 charset;
	UINT2 decimal;
} Field;

//////// The Core Data Struct
typedef struct {
	PyObject_HEAD
	PyObject *(*PFN_PyUnicode_Encode)(const Py_UNICODE *data, Py_ssize_t length,
			const char *errors);

	PyObject *Error;
	PyObject *SQLError;

	/* query-wide random string */
	void *sock;
	UINT1 *readerStartPtr, *readerReadPtr, *readerWritePtr, *readerEndPtr;
	UINT1 *writerStartPtr, *writerReadPtr, *writerWritePtr, *writerEndPtr;
	UINT1 *readerPktPtr;
	PyObject *fields;
	PyObject *rows;
	PyObject *curs;
	UINT4     nums;
	UINT1 columns;
	UINT1 nid; // next packet sequence id;
	UINT1 sqlstate[MY_SQLSTATE_LENGTH + 1]; //
	UINT2 lasterrno; // last errno;
	char *errmsg;

	UINT8 affectedRows;
	UINT8 insertId; /* id if insert on table with NEXTNR */
	UINT8 fieldCount;
	UINT4 serverStatus;
	UINT4 serverLanguage;
	UINT4 warningCount;

	/* session-wide random string */
	UINT1 ver;
	UINT4 cid; /* Con Id for connection in server */
	UINT4 tid; /* thread Id for connection in server */
	UINT4 pid;

	UINT1 serverLang;
	UINT2 serverCaps;
	UINT4 clientFlag;
	char scramble[MY_SCRAMBLE_LENGTH + 1];

	UINT4 timeout; /* set to 1 if automatic reconnect */
	UINT4 port; //ac: auto Commit
	char *host, *user, *pswd, *db, *serverVersion;
	bool ac;
	enum MY_CHARSETS charset;
} Con;

// for error and DEBUG
void pbuf(FILE *file, void *_offset, size_t len, int perRow) {
	size_t cnt = 0;
	int index;

	char *offset = (char *) _offset;
	char *end = offset + len;

	int orgPerRow = perRow;

	fprintf(file, "<< %u(0x%x) %p - %p --------------\n", (unsigned int)len, (unsigned int)len, _offset,
			_offset + (unsigned int)len);

	while (offset != end) {
		fprintf(file, "%08x: ", (unsigned int)cnt);

		if (end - offset < perRow) {
			perRow = end - offset;
		}

		for (index = 0; index < perRow; index++) {
			int chr = (unsigned char) *offset;

			if (isprint(chr)) {
				fprintf(file, "%c", chr);
			} else {
				fprintf(file, ".");
			}

			offset++;
		}

		offset -= perRow;

		for (index = perRow; index < orgPerRow; index++) {
			fprintf(file, " ");
		}

		fprintf(file, "    ");

		for (index = 0; index < perRow; index++) {
			int chr = (unsigned char) *offset;

			fprintf(file, "%02x ", chr);
			offset++;
		}

		fprintf(file, "\n");

		cnt += perRow;
	}
}

PyObject *API_error(Con *self, const char *msg) {
	PyObject *value;

	if (self->sock) {
		if (PyErr_Occurred()) {
			value = Py_BuildValue("(s,o,i,s)",
					"Python exception when local error is set",
					PyErr_Occurred(), self->lasterrno, self->errmsg);
			PyErr_Clear();
			PyErr_SetObject(amysql_Error, value);
			Py_DECREF(value);
			return NULL;
		}

		value = Py_BuildValue("(s,s)", msg, "Should not happen");
		PyErr_SetObject(PyExc_RuntimeError, value);
		Py_DECREF(value);
		return NULL;
	}

	if (PyErr_Occurred()) {
		return NULL;
	}

	value = Py_BuildValue("(s, s)", msg,
			"No error or Python error specified");
	PyErr_SetObject(PyExc_RuntimeError, value);
	if (value)
		Py_DECREF(value);
	return NULL;
}

// SHA1
inline void SHA1ProcessMessageBlock(register SHA1_CONTEXT *context) {
	register int t, idx; /* Loop counter		  */
	UINT4 temp; /* Temporary word value	  */
	UINT4 W[80]; /* Word sequence		  */
	UINT4 A, B, C, D, E; /* Word buffers		  */

	for (t = 0; t < 16; t++) {
		idx = t * 4;
		W[t] = context->Message_Block[idx] << 24;
		W[t] |= context->Message_Block[idx + 1] << 16;
		W[t] |= context->Message_Block[idx + 2] << 8;
		W[t] |= context->Message_Block[idx + 3];
	}

	for (t = 16; t < 80; t++) {
		W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
	}

	A = context->Intermediate_Hash[0];
	B = context->Intermediate_Hash[1];
	C = context->Intermediate_Hash[2];
	D = context->Intermediate_Hash[3];
	E = context->Intermediate_Hash[4];

	for (t = 0; t < 20; t++) {
		temp = SHA1CircularShift(5,A) + ((B & C) | ((~B) & D)) + E + W[t]
				+ SHA1_KEY[0];
		E = D;
		D = C;
		C = SHA1CircularShift(30,B);
		B = A;
		A = temp;
	}

	for (t = 20; t < 40; t++) {
		temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + SHA1_KEY[1];
		E = D;
		D = C;
		C = SHA1CircularShift(30,B);
		B = A;
		A = temp;
	}

	for (t = 40; t < 60; t++) {
		temp = (SHA1CircularShift(5,A) + ((B & C) | (B & D) | (C & D)) + E
				+ W[t] + SHA1_KEY[2]);
		E = D;
		D = C;
		C = SHA1CircularShift(30,B);
		B = A;
		A = temp;
	}

	for (t = 60; t < 80; t++) {
		temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + SHA1_KEY[3];
		E = D;
		D = C;
		C = SHA1CircularShift(30,B);
		B = A;
		A = temp;
	}

	context->Intermediate_Hash[0] += A;
	context->Intermediate_Hash[1] += B;
	context->Intermediate_Hash[2] += C;
	context->Intermediate_Hash[3] += D;
	context->Intermediate_Hash[4] += E;

	context->Message_Block_Index = 0;
}
inline void SHA1PadMessage(SHA1_CONTEXT *context) {
	int i = context->Message_Block_Index;

	if (i > 55) {
		context->Message_Block[i++] = 0x80;
		bzero((char*) &context->Message_Block[i],
				sizeof(context->Message_Block[0]) * (64 - i));
		context->Message_Block_Index = 64;

		/* This function sets context->Message_Block_Index to zero	*/
		SHA1ProcessMessageBlock(context);

		bzero((char*) &context->Message_Block[0],
				sizeof(context->Message_Block[0]) * 56);
		context->Message_Block_Index = 56;
	} else {
		context->Message_Block[i++] = 0x80;
		bzero((char*) &context->Message_Block[i],
				sizeof(context->Message_Block[0]) * (56 - i));
		context->Message_Block_Index = 56;
	}

	context->Message_Block[56] = (UINT1) (context->Length >> 56);
	context->Message_Block[57] = (UINT1) (context->Length >> 48);
	context->Message_Block[58] = (UINT1) (context->Length >> 40);
	context->Message_Block[59] = (UINT1) (context->Length >> 32);
	context->Message_Block[60] = (UINT1) (context->Length >> 24);
	context->Message_Block[61] = (UINT1) (context->Length >> 16);
	context->Message_Block[62] = (UINT1) (context->Length >> 8);
	context->Message_Block[63] = (UINT1) (context->Length);

	SHA1ProcessMessageBlock(context);
}
static int sha1_reset(SHA1_CONTEXT *context) {
	context->Length = 0;
	context->Message_Block_Index = 0;

	context->Intermediate_Hash[0] = sha_const_key[0];
	context->Intermediate_Hash[1] = sha_const_key[1];
	context->Intermediate_Hash[2] = sha_const_key[2];
	context->Intermediate_Hash[3] = sha_const_key[3];
	context->Intermediate_Hash[4] = sha_const_key[4];

	context->Computed = 0;
	context->Corrupted = 0;

	return SHA_SUCCESS;
}
static int sha1_result(SHA1_CONTEXT *context,
		UINT1 Message_Digest[MY_SHA1_HASH_SIZE]) {
	UINT4 i;
	if (!context->Computed) {
		SHA1PadMessage(context);/* message may be sensitive, clear it out */
		for (i = 0; i < 64; ++i)
			context->Message_Block[i] = 0;
		context->Length = 0; /* and clear length  */
		context->Computed = 1;
	}

	for (i = 0; i < MY_SHA1_HASH_SIZE; i++)
		Message_Digest[i] = (INT1) (context->Intermediate_Hash[i >> 2]
				>> 8 * (3 - (i & 0x03)));
	return SHA_SUCCESS;
}
static int sha1_input(SHA1_CONTEXT *context, const UINT1 *message_array,
		unsigned length) {
	if (!length)
		return SHA_SUCCESS;
	while (length--) {
		context->Message_Block[context->Message_Block_Index++] = (*message_array
				& 0xFF);
		context->Length += 8; /* Length is in bits */

		if (context->Message_Block_Index == 64) {
			SHA1ProcessMessageBlock(context);
		}
		message_array++;
	}
	return SHA_SUCCESS;
}
static void scramble_password(UINT1 *to, const UINT1 *message, const UINT1 *password) {
	SHA1_CONTEXT sha1_context;
	UINT1 hash_stage1[MY_SHA1_HASH_SIZE];
	UINT1 hash_stage2[MY_SHA1_HASH_SIZE];
	int index = 0;

	sha1_reset(&sha1_context);
	sha1_input(&sha1_context, (UINT1 *) password, (UINT4) strlen(password));
	sha1_result(&sha1_context, hash_stage1);
	sha1_reset(&sha1_context);
	sha1_input(&sha1_context, hash_stage1, MY_SHA1_HASH_SIZE);
	sha1_result(&sha1_context, hash_stage2);
	sha1_reset(&sha1_context);
	sha1_input(&sha1_context, (const UINT1 *) message, MY_SCRAMBLE_LENGTH);
	sha1_input(&sha1_context, hash_stage2, MY_SHA1_HASH_SIZE);
	sha1_result(&sha1_context, to);
	for (index = 0; index < MY_SHA1_HASH_SIZE; ++index)to[index] ^= hash_stage1[index];/* xor allows 'from' and 'to' overlap: lets take advantage of it */
}

//////// Python socket interface
inline void *
 API_getSocket() {
	PyObject *sockobj;
	sockobj = PyObject_Call(sockclass, PyTuple_New(0), NULL);
	return sockobj;
}
inline int
API_setTimeout(void *sock, int timeoutSec) {
	PyObject *intobj;
	PyObject *retobj;
	PyObject *methodObj;

	intobj = PyFloat_FromDouble((double) timeoutSec);

	methodObj = PyString_FromString("settimeout");
	retobj = PyObject_CallMethodObjArgs((PyObject *) sock, methodObj, intobj,
			NULL);
	Py_DECREF(intobj);
	Py_DECREF(methodObj);
	if (retobj == NULL) {
		PyErr_Clear();
		return 0;
	}

	Py_DECREF(retobj);
	return 1;

}
inline bool API_closeSocket(void *sock) {
	PyObject *res = PyObject_CallMethod((PyObject *) sock, "close", NULL);

	if (res == NULL)
		return 0;

	Py_DECREF(res);
	Py_DECREF((PyObject *) sock);
	return 1;
}
inline bool API_setblockingSocket(void *sock, bool flag) {
	PyObject *res = PyObject_CallMethod((PyObject *) sock, "setblocking", "i",
			&flag);

	if (res == NULL)
		return 0;

	Py_DECREF(res);
	Py_DECREF((PyObject *) sock);
	return 1;
}
inline int API_connectSocket(void *sock, const char *host, int port) {
	PyObject *res;
	PyObject *addrTuple;
	PyObject *connectStr;

	addrTuple = PyTuple_New(2);
	PyTuple_SET_ITEM(addrTuple, 0, PyString_FromString(host));
	PyTuple_SET_ITEM(addrTuple, 1, PyInt_FromLong(port));

	connectStr = PyString_FromString("connect_ex");
	res = PyObject_CallMethodObjArgs((PyObject *) sock, connectStr, addrTuple,
			NULL);

	Py_DECREF(connectStr);
	Py_DECREF(addrTuple);

	if (res == NULL)
		return 0;
	Py_DECREF(res);
	return 1;
}
inline int API_recvSocket(void *sock,UINT1 *buffer, size_t size) {
	int ret;
	PyObject *res;
	if ((res = PyObject_CallMethodObjArgs((PyObject *) sock,
			PyString_FromString("recv"), PyInt_FromLong(size), NULL)) == NULL)
		return -1;
	ret = (long) PyString_GET_SIZE(res);
	memcpy(buffer, PyString_AS_STRING(res), ret);
	Py_DECREF(res);
	return ret;
}
inline int API_sendSocket(void *sock, const char *buffer, int cbBuffer) {
	PyObject *res;
	PyObject *pybuffer;
	PyObject *funcStr;
	int ret;

	funcStr = PyString_FromString("send");
	pybuffer = PyString_FromStringAndSize(buffer, cbBuffer);
	res = PyObject_CallMethodObjArgs((PyObject *) sock, funcStr, pybuffer,
			NULL);
	Py_DECREF(funcStr);
	Py_DECREF(pybuffer);

	if (res == NULL) {
		return -1;
	}

	ret = (int) PyInt_AsLong(res);
	Py_DECREF(res);
	return ret;
}

//////// Con buffers( reader/writer ) interface
inline UINT1 readerUINT1(Con *self) {
	assert(self->readerReadPtr + 1 < self->readerPktPtr);
	return *self->readerReadPtr++;
}
inline UINT2 readerUINT2(Con *self) {
	assert(self->readerReadPtr + 2 <= self->readerPktPtr);
	UINT2 ret = *((UINT2 *)self->readerReadPtr);
	self->readerReadPtr += 2;
	return ret;
}
inline UINT4 readerUINT3(Con *self) {
	assert(self->readerReadPtr + 3 < self->readerPktPtr);
	UINT4 ret = 0xffffff & *((UINT4 *) self->readerReadPtr);
	self->readerReadPtr += 3;
	return ret;
}
inline UINT4 readerUINT4(Con *self) {
	assert(self->readerReadPtr + 4 <= self->readerPktPtr);
	UINT4 ret = *((UINT4 *) self->readerReadPtr);
	self->readerReadPtr += 4;
	return ret;
}
inline UINT4 Con_WriteUINT4(Con *self) {
	assert(self->writerWritePtr + 4 < self->writerEndPtr);
	UINT4 ret = *((UINT4 *) self->readerReadPtr);
	self->readerReadPtr += 4;
	return *self->readerReadPtr++;
	return ret;
}
inline UINT8 readerCodedLength(Con *self) {
	assert(self->readerReadPtr < self->readerPktPtr);
	register UINT1 *pos = self->readerReadPtr;

	switch (*pos) {
	case 0xfe:
		self->readerReadPtr += 9;
		return *((UINT8 *) (pos + 1));
	case 0xfd:
		self->readerReadPtr += 4;
		return pos[1] | pos[2] << 8 | pos[3] << 16;
	case 0xfc:
		self->readerReadPtr += 3;
		return *((UINT2 *) pos);
	case 0xfb:
		self->readerReadPtr++;
		return MY_NULL_LENGTH;
	default:
		self->readerReadPtr++;
		return *pos;
	}
}
inline ulong readerFieldLength(Con *self) {
	assert(self->readerReadPtr < self->readerPktPtr);
	register UINT1 *pos = self->readerReadPtr;
	switch (*pos) {
	case 0xfe:
		self->readerReadPtr += 9;
		return *((const UINT4 *) (pos + 1));
	case 0xfd:
		self->readerReadPtr += 4;
		return 0xffffff & *((const UINT4 *) (pos + 1));
	case 0xfc:
		self->readerReadPtr += 3;
		return *((const UINT2 *) (pos + 1));
	case 0xfb:
		self->readerReadPtr++;
		return MY_NULL_LENGTH;
	default:
		self->readerReadPtr++;
		return (ulong) *pos;
	}
}
inline UINT1 *readerBytes(Con *self, size_t size) {
	assert(
			self->readerReadPtr + size < self->readerPktPtr
					&& self->readerPktPtr <= self->readerWritePtr);
	UINT1 *ret = (UINT1 *) self->readerReadPtr;
	self->readerReadPtr += size;
	return ret;
}
inline char *readerNTString(Con *self) {
	assert(
			self->readerReadPtr < self->readerPktPtr
					&& self->readerPktPtr <= self->readerEndPtr);
	char *ret = (char *)self->readerReadPtr;
	while (self->readerReadPtr < self->readerPktPtr)
		if ((*self->readerReadPtr++) == '\0')
			return ret;
	assert(0);
	return NULL;
}
#define readerReset(con) do{if(!con->readerStartPtr || con->readerEndPtr -con->readerStartPtr>MY_BUFFER_SIZE){MyRealloc(con->readerStartPtr, MY_BUFFER_SIZE);con->readerEndPtr= con->readerStartPtr +MY_BUFFER_SIZE;};con->nid=0;con->readerPktPtr=con->readerReadPtr=con->readerWritePtr=con->readerStartPtr;}while(0)
#define writerINT1(con,u) do{*((UINT1*)con->writerWritePtr)=(u);con->writerWritePtr++;}while(0)
#define writerINT4(con,u) do{*((UINT4*)con->writerWritePtr)=(u);con->writerWritePtr+=4;}while(0)
#define writerSize(con) (con->writerEndPtr-con->writerStartPtr)
#define writerIsDone(con)  (con->writerReadPtr ==con->writerWritePtr)
#define writerPush(con, ptr, sz)  do{assert(con->writeWritePtr +sz>0 && con->writeWritePtr +sz<con->writerEndPtr);memcpy(con->writeWritePtr,p,sz);con->writeWritePtr+=sz;}while(0)
#define writerPull(con,sz)  do{assert(con->writeReadPtr+sz>0 && writeReadPtr+sz<=writeWritePtr);writeReadPtr +=sz;}while(0)
inline void writerReset(Con *self) {
	if (!self->writerStartPtr
			|| self->writerEndPtr - self->writerStartPtr <= MY_PACKET_MAX
			|| self->writerEndPtr - self->writerStartPtr >= MY_BUFFER_MAX) {
		MyRealloc(self->writerStartPtr, MY_BUFFER_SIZE);
		self->writerWritePtr = self->writerReadPtr = self->writerStartPtr;
		self->writerEndPtr = self->writerStartPtr + MY_BUFFER_SIZE;
	}
	self->writerWritePtr = self->writerReadPtr;
	*((UINT4*) self->writerWritePtr) = 0;
	self->writerWritePtr += MY_HEADER_SIZE;
}
inline void writerFinalize(Con *self, UINT4 sid) {
	*((UINT4 *) self->writerReadPtr) = 0xffffff
			& ((UINT4) (self->writerWritePtr - self->writerReadPtr
					- MY_HEADER_SIZE));
	self->writerReadPtr[3] = (UINT1) sid;
}
inline bool writerNTString(Con *self, char *p) {
	if (!p) {
		assert(self->writerWritePtr < self->writerEndPtr);
		*(self->writerWritePtr++) = '\0';
	}
	while (*p && self->writerWritePtr < self->writerEndPtr)
		*(self->writerWritePtr++) = *p++;
	assert(self->writerWritePtr < self->writerEndPtr);
	*(self->writerWritePtr)++ = '\0';
	return true;
}
inline bool writerBytes(Con *self, char *p, UINT4 sz) {
	if (!p || sz == 0 || self->writerEndPtr - self->writerWritePtr < sz)
		return false;
	while (self->writerWritePtr < self->writerEndPtr && sz-- > 0)
		*(self->writerWritePtr++) = *p++;
	if (sz != 0)
		return false;
	return true;
}

inline INT4 parseINT4(UINT1 *start, UINT1 *end) {
	INT4 intValue = 0;
	INT4 intNeg = 1;
	INT4 chr;

	if (*start == '-') {
		start++;
		intNeg = -1;
	}

	while (start < end) {
		chr = (INT4) (unsigned char) *(start++);
		switch (chr) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			intValue = intValue * 10 + (INT4) (chr - 48);
			break;

		default:
			break;
		}
	}

	return intValue * intNeg;
}
inline INT8 parseINT8(UINT1 *start, char *end) {
	INT8 intValue = 0;
	INT8 intNeg = 1;
	INT8 chr;

	if (*start == '-') {
		start++;
		intNeg = -1;
	}

	while (start < end) {
		chr = (INT4) (unsigned char) *(start++);

		switch (chr) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			intValue = intValue * 10 + (INT8) (chr - 48);
			break;

		default:
			break;
		}
	}

	return intValue * intNeg;
}



static PyObject *Con_Connect(Con *self, PyObject *args);
int Con_Constructor(Con *self, PyObject *args) {
	self->tid = 0;
	self->sock = NULL;
	self->Error = amysql_Error;
	self->SQLError = amysql_SQLError;
	self->PFN_PyUnicode_Encode = NULL;
	readerReset(self);
	writerReset(self);
	if (PyErr_Occurred()) {
		PyErr_Format(PyExc_RuntimeError, "Exception is set for no error in %s",
				__FUNCTION__);
		return -1;
	}

	if (args && PyObject_IsTrue(args))
		Con_Connect(self, args);
	Py_INCREF(self);
	return 0;
}
static int Con_Clear(Con *self) {
    Py_CLEAR(self->rows);
    Py_CLEAR(self->fields);
    Py_CLEAR(self->sock);
    return 0;
}
static PyObject *
Con_New(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    Con *self;
    self = (Con *)type->tp_alloc(type, 0);
    return (PyObject *)self;
}
static void Con_Destructor(Con *self) {
	if (self->sock) {
		self->tid = 0;
		writerReset(self);
		writerINT1(self, 0x1);
		writerFinalize(self, 0);
		API_sendSocket(self->sock, self->writerReadPtr,
				self->writerWritePtr - self->writerReadPtr);
		if(self->readerStartPtr)MyFree(self->readerStartPtr);
		if(self->writerStartPtr)MyFree(self->writerStartPtr);
		API_closeSocket(self->sock);
		Con_Clear(self);
		self->readerStartPtr=self->readerReadPtr=self->readerPktPtr=self->readerWritePtr=self->readerEndPtr \
				=self->writerStartPtr=self->writerReadPtr=self->writerWritePtr=self->writerEndPtr \
				=self->rows =self->fields =self->sock =NULL;
	}
}
static int
Con_Traverse(Con *self, visitproc visit, void *arg)
{
    if(self->rows)Py_VISIT(self->rows);
    if(self->fields)Py_VISIT(self->fields);
    return 0;
}

inline static PyObject *Con_PacketRecv(Con *self, bool skipCols) {
	register UINT1 *pos;
	register ulong cols, i, pktlen, remain;
	register long len;
	register Field *fields = NULL, *col = NULL;
	register PyObject *row, *valobj, *sobj;
	static long RSLen, PRLen, WPLen;
	int year;
	int month;
	int day;
	int hour;
	int minute;
	int second;
	char temp[20];

	self->serverStatus &= ~SERVER_MORE_RESULTS_EXISTS;
	pos = self->readerReadPtr = self->readerPktPtr;
	if (self->readerWritePtr - self->readerPktPtr < MY_HEADER_SIZE) {
		if (self->readerEndPtr - self->readerPktPtr < MY_HEADER_SIZE) {
			do {
				len = self->readerEndPtr - self->readerStartPtr;
				if (len <= 0) {
					len = MY_BUFFER_SIZE;
				} else
					len <<= 1;
				assert(0 < len && len <= MY_BUFFER_MAX);
				RSLen = self->readerReadPtr - self->readerStartPtr;
				PRLen = self->readerPktPtr - self->readerReadPtr;
				WPLen = self->readerWritePtr - self->readerPktPtr;
				MyRealloc(self->readerStartPtr, len);
				self->readerEndPtr = self->readerStartPtr + len;
				self->readerReadPtr = self->readerStartPtr + RSLen;
				self->readerPktPtr = self->readerReadPtr + PRLen;
				self->readerWritePtr = self->readerPktPtr + WPLen;
			} while (self->readerEndPtr - self->readerPktPtr
					< MY_HEADER_SIZE);
		}
		do {
			len = API_recvSocket(self->sock, self->readerWritePtr,
					self->readerEndPtr - self->readerWritePtr);
			if (len <= 0L) {
				break;
			} else
				self->readerWritePtr += len;
		} while (self->readerWritePtr - self->readerPktPtr < MY_HEADER_SIZE);
	}
	remain = 0xffffff & *((UINT4 *) pos);
	if (self->readerWritePtr - self->readerPktPtr < remain) {
		if (self->readerEndPtr - self->readerPktPtr < remain) {
			do {
				len = self->readerEndPtr - self->readerStartPtr;
				if (len <= 0) {
					len = MY_BUFFER_SIZE;
				} else
					len = len << 1;
				assert(0 < len && len <= MY_BUFFER_MAX);
				RSLen = self->readerReadPtr - self->readerStartPtr;
				PRLen = self->readerPktPtr - self->readerReadPtr;
				WPLen = self->readerWritePtr - self->readerPktPtr;
				MyRealloc(self->readerStartPtr, len);
				self->readerEndPtr = self->readerStartPtr + len;
				self->readerReadPtr = self->readerStartPtr + RSLen;
				self->readerPktPtr = self->readerReadPtr + PRLen;
				self->readerWritePtr = self->readerPktPtr + WPLen;
			} while (self->readerEndPtr - self->readerPktPtr < remain);
		}
		do {
			len = API_recvSocket(self->sock, self->readerWritePtr,
					self->readerEndPtr - self->readerWritePtr);
			if (len <= 0L) {
				break;
			} else
				self->readerWritePtr += len;
		} while (self->readerWritePtr - self->readerPktPtr < remain);
	}
	self->nid = pos[3];
	self->readerReadPtr = pos = pos + MY_HEADER_SIZE;
	self->readerPktPtr = pos + remain;

	if (*pos == 0x0) { // OK
		self->readerReadPtr = pos+1;
		self->affectedRows = readerCodedLength(self);
		self->insertId     = readerCodedLength(self);
		self->serverStatus = readerUINT2(self);
		self->warningCount = readerUINT2(self);
		self->readerReadPtr=self->readerPktPtr;
		fprintf(stderr, "\nAFFECTED ROWS: %llu  INSERT ID: %llu   STATUS: %u  WARNC: %u \n",
				self->affectedRows, self->insertId, self->serverStatus,
				self->warningCount);
		return self;
	} else if (*pos == 0xff) { // Error
		self->serverStatus &= ~SERVER_MORE_RESULTS_EXISTS;
		if (remain > 3) {
			self->lasterrno =*((UINT2 *) (pos + 1));
			pos += 3;
			if (*(pos++) == '#') {
				self->sqlstate[MY_SQLSTATE_LENGTH] = '\0';
				for (len = 0; len < MY_SQLSTATE_LENGTH; ++len)
					self->sqlstate[len] = *(pos++);
				self->errmsg = pos;
			} else {
				self->sqlstate[0] = 'H';
				self->sqlstate[1] = 'Y';
				self->sqlstate[2] = '0';
				self->sqlstate[3] = '0';
				self->sqlstate[4] = '0';
				self->sqlstate[5] = '\0';
				self->errmsg = pos;
			}
		};
		readerReset(self);
		THROW("Got error: %d/%s (%s)", self->lasterrno, self->sqlstate, self->errmsg);
		return NULL;
	} else if (*pos == 0xfe && remain <8) { // EOF Packet
		self->readerReadPtr= pos+1;
		self->warningCount = readerUINT2(self);
		self->serverStatus = readerUINT2(self);
		self->readerReadPtr= self->readerPktPtr;
		if (self->serverStatus & SERVER_MORE_RESULTS_EXISTS)
			return self;
		THROW("Unexpected EOF when decoding result");
	}

	if (!(self->serverStatus & SERVER_STATUS_AUTOCOMMIT))
		self->serverStatus |= SERVER_STATUS_IN_TRANS;
	switch (*pos) {
	case 0xfe:
		cols = *((UINT4 *) (pos + 1));
		pos += 9;
		break;
	case 0xfd:
		cols = 0xffffff & *((UINT4 *) (pos + 1));
		pos += 4;
		break;
	case 0xfc:
		cols = *((UINT2 *) (pos + 1));
		pos += 3;
		break;
	case 0xfb:
		cols = MY_NULL_LENGTH;
		pos++;
		break;
	default:
		cols = *pos++;
		break;
	}
	assert(pos == self->readerPktPtr);
	self->readerReadPtr = pos;

	if (self->rows){Py_DECREF(self->rows);self->rows=NULL;}
	if (self->fields){Py_DECREF(self->fields);self->fields=NULL;}
	self->rows = PyList_New(0);
	self->fields = PyTuple_New(cols);
	if (self->rows && self->fields){
		Py_INCREF(self->rows);
		Py_INCREF(self->fields);
	} else if (PyErr_Occurred()) {
		PyErr_Format(PyExc_ValueError, "Parse packet field: %s", pos);
		return 0;
	}

	MyRealloc(fields, cols*sizeof(Field));
	for (i = 0; i <= cols; i++) { // Fields
		pos = self->readerReadPtr = self->readerPktPtr;
		if (self->readerWritePtr - self->readerPktPtr < MY_HEADER_SIZE) {
			if (self->readerEndPtr - self->readerPktPtr < MY_HEADER_SIZE) {
				do {
					len = self->readerEndPtr - self->readerStartPtr;
					if (len <= 0) {
						len = MY_BUFFER_SIZE;
					} else
						len <<= 1;
					assert(0 < len && len <= MY_BUFFER_MAX);
					RSLen = self->readerReadPtr - self->readerStartPtr;
					PRLen = self->readerPktPtr - self->readerReadPtr;
					WPLen = self->readerWritePtr - self->readerPktPtr;
					MyRealloc(self->readerStartPtr, len);
					self->readerEndPtr = self->readerStartPtr + len;
					self->readerReadPtr = self->readerStartPtr + RSLen;
					self->readerPktPtr = self->readerReadPtr + PRLen;
					self->readerWritePtr = self->readerPktPtr + WPLen;
				} while (self->readerEndPtr - self->readerPktPtr
						< MY_HEADER_SIZE);
			}
			do {
				len = API_recvSocket(self->sock, self->readerWritePtr,
						self->readerEndPtr - self->readerWritePtr);
				if (len <= 0L) {
					break;
				} else
					self->readerWritePtr += len;
			} while (self->readerWritePtr - self->readerPktPtr < MY_HEADER_SIZE);
		}
		remain = 0xffffff & *((UINT4 *) pos);
		self->nid = pos[3];
		self->readerPktPtr = pos = pos + MY_HEADER_SIZE;
		if (self->readerWritePtr - self->readerPktPtr < remain) {
			if (self->readerEndPtr - self->readerPktPtr < remain) {
				do {
					len = self->readerEndPtr - self->readerStartPtr;
					if (len <= 0) {
						len = MY_BUFFER_SIZE;
					} else
						len = len << 1;
					assert(0 < len && len <= MY_BUFFER_MAX);
					RSLen = self->readerReadPtr - self->readerStartPtr;
					PRLen = self->readerPktPtr - self->readerReadPtr;
					WPLen = self->readerWritePtr - self->readerPktPtr;
					MyRealloc(self->readerStartPtr, len);
					self->readerEndPtr = self->readerStartPtr + len;
					self->readerReadPtr = self->readerStartPtr + RSLen;
					self->readerPktPtr = self->readerReadPtr + PRLen;
					self->readerWritePtr = self->readerPktPtr + WPLen;
				} while (self->readerEndPtr - self->readerPktPtr < remain);
			}
			do {
				len = API_recvSocket(self->sock, self->readerWritePtr,
						self->readerEndPtr - self->readerWritePtr);
				if (len <= 0L) {
					break;
				} else
					self->readerWritePtr += len;
			} while (self->readerWritePtr - self->readerPktPtr < remain);
		}
		self->readerReadPtr =pos;
		self->readerPktPtr = pos + remain;
		if (*pos == 0xfe) { // fields DONE!
			assert(i == cols);
			break;
		}
		switch (*pos) { //UINT1 *catalog
		case 0xfd:
			pos += 4 + 0xffffff & *((const UINT4 *) (pos + 1));
			break;
		case 0xfc:
			pos += 3 + *((const UINT2 *) (pos + 1));
			break;
		case 0xfb:
			pos += 1 + MY_NULL_LENGTH;
			break;
		default:
			pos += 1 + *pos;
			break;
		};
		switch (*pos) { //UINT1 *db : scheme name
		case 0xfe:
			pos += 9 + *((const UINT4 *) (pos + 1));
			break;
		case 0xfd:
			pos += 4 + 0xffffff & *((const UINT4 *) (pos + 1));
			break;
		case 0xfc:
			pos += 3 + *((const UINT2 *) (pos + 1));
			break;
		case 0xfb:
			pos += 1 + MY_NULL_LENGTH;
			break;
		default:
			pos += 1 + *pos;
			break;
		}
		switch (*pos) { //UINT1 *table : virtual table name
		case 0xfe:
			pos += 9 + *((const UINT4 *) (pos + 1));
			break;
		case 0xfd:
			pos += 4 + 0xffffff & *((const UINT4 *) (pos + 1));
			break;
		case 0xfc:
			pos += 3 + *((const UINT2 *) (pos + 1));
			break;
		case 0xfb:
			pos += 1 + MY_NULL_LENGTH;
			break;
		default:
			pos += 1 + *pos;
			break;
		}
		switch (*pos) { //UINT1 *org_table : physical table name
		case 0xfe:
			pos += 9 + *((const UINT4 *) (pos + 1));
			break;
		case 0xfd:
			pos += 4 + 0xffffff & *((const UINT4 *) (pos + 1));
			break;
		case 0xfc:
			pos += 3 + *((const UINT2 *) (pos + 1));
			break;
		case 0xfb:
			pos += 1 + MY_NULL_LENGTH;
			break;
		default:
			pos += 1 + *pos;
			break;
		}
		switch (*pos) { //UINT1 *name
		case 0xfe:
			pos += 9;
			len = *((const UINT4 *) (pos + 1));
			break;
		case 0xfd:
			pos += 4;
			len = 0xffffff & *((const UINT4 *) (pos + 1));
			break;
		case 0xfc:
			pos += 3;
			len = *((const UINT2 *) (pos + 1));
			break;
		case 0xfb:
			pos++;
			len = MY_NULL_LENGTH;
			break;
		default:
			len = *pos++;
			break;
		}
		fields[i].name = PyString_FromStringAndSize(pos, len);
		if (fields[i].name == NULL) {
			if (PyErr_Occurred()) {
				PyErr_Format(PyExc_ValueError, "Parse packet field: %s",
						pos);
				return 0;
			}
		}else pos += len; //
		switch (*pos) { //UINT1 *org_name
		case 0xfe:
			pos += 9 + *((const UINT4 *) (pos + 1));
			break;
		case 0xfd:
			pos += 4 + 0xffffff & *((const UINT4 *) (pos + 1));
			break;
		case 0xfc:
			pos += 3 + *((const UINT2 *) (pos + 1));
			break;
		case 0xfb:
			pos += 1 + MY_NULL_LENGTH;
			break;
		default:
			pos += 1 + *pos;
			break;
		}
		assert(*pos++ == 0xc);
		fields[i].charset = *((UINT2 *) pos);
		pos += 2; //UINT2 charset
		pos += 4; //UINT4 length =
		fields[i].type = *pos++; //UINT1 type =
		fields[i].flags = *((UINT2 *) pos); pos += 2; //UINT1 flags =
		fields[i].decimal = *pos; //UINT2 decimals =;
		self->readerReadPtr = self->readerPktPtr;

		PyTuple_SET_ITEM(self->fields, i, fields[i].name);
	}

	self->nums =0;
	while (1) { // ROWS
		pos = self->readerReadPtr = self->readerPktPtr;
		if (self->readerWritePtr - self->readerPktPtr < MY_HEADER_SIZE) {
			if (self->readerEndPtr - self->readerPktPtr < MY_HEADER_SIZE) {
				do {
					len = self->readerEndPtr - self->readerStartPtr;
					if (len <= 0) {
						len = MY_BUFFER_SIZE;
					} else
						len = len << 1;
					assert(0 < len && len <= MY_BUFFER_MAX);
					RSLen = self->readerReadPtr - self->readerStartPtr;
					PRLen = self->readerPktPtr - self->readerReadPtr;
					WPLen = self->readerWritePtr - self->readerPktPtr;
					MyRealloc(self->readerStartPtr, len);
					self->readerEndPtr = self->readerStartPtr + len;
					self->readerReadPtr = self->readerStartPtr + RSLen;
					self->readerPktPtr = self->readerReadPtr + PRLen;
					self->readerWritePtr = self->readerPktPtr + WPLen;
				} while (self->readerEndPtr - self->readerPktPtr
						< MY_HEADER_SIZE);
			}
			do {
				len = API_recvSocket(self->sock, self->readerWritePtr,
						self->readerEndPtr - self->readerWritePtr);
				if (len <= 0L) {
					break;
				} else
					self->readerWritePtr += len;
			} while (self->readerWritePtr - self->readerPktPtr
					< MY_HEADER_SIZE);
		}
		remain = 0xffffff & *((UINT4 *) pos);
		self->nid = pos[3];
		self->readerPktPtr = pos = pos + MY_HEADER_SIZE;
		if (self->readerWritePtr - self->readerPktPtr < remain) {
			if (self->readerEndPtr - self->readerPktPtr < remain) {
				do {
					len = self->readerEndPtr - self->readerStartPtr;
					if (len <= 0) {
						len = MY_BUFFER_SIZE;
					} else
						len = len << 1;
					assert(0 < len && len <= MY_BUFFER_MAX);
					RSLen = self->readerReadPtr - self->readerStartPtr;
					PRLen = self->readerPktPtr - self->readerReadPtr;
					WPLen = self->readerWritePtr - self->readerPktPtr;
					MyRealloc(self->readerStartPtr, len);
					self->readerEndPtr = self->readerStartPtr + len;
					self->readerReadPtr = self->readerStartPtr + RSLen;
					self->readerPktPtr = self->readerReadPtr + PRLen;
					self->readerWritePtr = self->readerPktPtr + WPLen;
				} while (self->readerEndPtr - self->readerPktPtr
						< remain);
			}
			do {
				len = API_recvSocket(self->sock, self->readerWritePtr,
						self->readerEndPtr - self->readerWritePtr);
				if (len <= 0L) {
					break;
				} else
					self->readerWritePtr += len;
			} while (self->readerWritePtr - self->readerPktPtr < remain);
		}
		self->readerPktPtr = pos + remain;
		self->readerReadPtr = pos;
		 if (*pos == 0xff) { // ERROR packet
							if (self->rows){Py_DECREF(self->rows);self->rows=NULL;}
							if (self->fields){Py_DECREF(self->fields);self->fields=NULL;}
							return self;
		}else if (*pos == 0xfe || remain < 8) {// EOF packet
			if (self->serverStatus & SERVER_MORE_RESULTS_EXISTS) {
				self->warningCount = readerUINT2(self);
				self->serverStatus = readerUINT2(self);
				self->readerReadPtr = self->readerPktPtr;
				return self;
			}
			self->readerReadPtr = self->readerPktPtr;
			break;
		}else if (*pos ==0x0 || *pos == 0xfb){// OK|NULL packet
			self->readerReadPtr = self->readerPktPtr;
			break;
		}

		row = PyTuple_New(cols);
		for (i =0; i < cols; i++) {
			col = fields + i;
			if (*pos == 0xfb){ /* null field */
				PyTuple_SET_ITEM(row, i, Py_None);
				pos++;
				continue;
			}
			switch (*pos){
				case 0xfe:
					len = *((const UINT4 *) (pos + 1));
					pos += 9;
					break;
				case 0xfd:
					len = 0xffffff & *((const UINT4 *) (pos + 1));
					pos += 4;
					break;
				case 0xfc:
					len = *((const UINT2 *) (pos + 1));
					pos += 3;
					break;
				default:
					len = *pos;
					pos++;
					break;
			}
			switch (col->type) {
			case MFTYPE_NULL://PyNone:
				valobj = Py_None;
				Py_INCREF(valobj);
				break;

			case MFTYPE_TINY://PyInt
			case MFTYPE_SHORT:
			case MFTYPE_LONG:
			case MFTYPE_INT24:
				valobj = PyInt_FromLong(parseINT4(pos, pos + len));
				break;

			case MFTYPE_LONGLONG://PyLong
				valobj = PyLong_FromLongLong(
						parseINT8(pos, pos + len));
				break;

			case MFTYPE_FLOAT://PyFloat
			case MFTYPE_DOUBLE:
				sobj = PyString_FromStringAndSize(pos, len);//FIXME: Too slow
				valobj = PyFloat_FromString(sobj, NULL);
				Py_DECREF(sobj);
				break;

			case MFTYPE_DATE:
				year = parseINT4(pos, pos + 4);
				if (year < 1) {
					valobj = Py_None;
					Py_INCREF(valobj);
					break;
				}
				month = parseINT4(pos + 5, pos + 7);
				day = parseINT4(pos + 8, pos + 10);
				valobj = PyDate_FromDate(year, month, day);
				break;

			case MFTYPE_DATETIME:
				//9999-12-31 23:59:59
				memcpy(temp, pos, len);
				temp[len] = '\0';
				year = parseINT4(pos, pos + 4);
				month = parseINT4(pos + 5, pos + 7);
				day = parseINT4(pos + 8, pos + 10);
				hour = parseINT4(pos + 11, pos + 13);
				minute = parseINT4(pos + 14, pos + 16);
				second = parseINT4(pos + 17, pos + 19);
				if (year < 1) {
					valobj = Py_None;
					Py_IncRef(valobj);
					break;
				}
				valobj = PyDateTime_FromDateAndTime(year, month, day,
						hour, minute, second, 0);
				break;

			case MFTYPE_TIMESTAMP:// We ignore these
			case MFTYPE_TIME:
			case MFTYPE_YEAR:
			case MFTYPE_NEWDATE:
				// Fall through for string encoding
				//Blob goes as String
			case MFTYPE_TINY_BLOB:
			case MFTYPE_MEDIUM_BLOB:
			case MFTYPE_LONG_BLOB:
			case MFTYPE_BLOB:
				if (col->flags & MFFLAG_BINARY_FLAG) {
					valobj = PyString_FromStringAndSize(pos, len);
					break;
				}
			case MFTYPE_VAR_STRING://PyString family
			case MFTYPE_VARCHAR:
			case MFTYPE_STRING:
				switch (col->charset) {
				case MCS_binary:
					valobj=PyString_FromStringAndSize(pos, len);
					break;
				case MCS_ascii_general_ci: //11,
				case MCS_ascii_bin: //65,
					valobj=PyUnicode_DecodeASCII(pos, len, NULL);
					break;
				case MCS_utf8_general_ci: //33,
				case MCS_utf8_bin: //83,
				case MCS_utf8_unicode_ci: //192,
					valobj=PyUnicode_DecodeUTF8(pos, len, NULL);
					break;
				case MCS_utf16_general_ci: //54,
				case MCS_utf16_bin: //55,
				case MCS_utf16_unicode_ci: //101,
					valobj=PyUnicode_DecodeUTF16(pos, len/2, NULL, NULL);
					break;
				case MCS_utf32_general_ci: //60,
				case MCS_utf32_bin: //61,
				case MCS_utf32_unicode_ci: //160,
					valobj=PyUnicode_DecodeUTF32(pos, len / 4, NULL, NULL);
					break;
				default:
					fprintf(stderr,"Exception call:%s (%s:%l) :\n",(char *)__FUNCTION__, (char *)__FILE__, (long)__LINE__);
					fprintf(stderr,"Error decoding field: TYPE: %02x  CHRS: %02x  FLAG: %02x  NAME: %s\n", col->type, col->charset, col->flags, PyString_AsString(col->name));
					return;
				}
				break;

			case MFTYPE_ENUM:
			case MFTYPE_GEOMETRY:
			case MFTYPE_BIT:
			case MFTYPE_NEWDECIMAL:
			case MFTYPE_SET:
			case MFTYPE_DECIMAL:
				// Fall through for string encoding
				valobj = PyString_FromStringAndSize(pos, len);
				break;
			default:
				fprintf(stdout, "COL ERROR: TYPE: %x  CHAS:%x  NAME: %s\n", col->type, col->charset, col->name);
			}
			pos += len;
			PyTuple_SET_ITEM(row, i, valobj);
		}
		Py_INCREF(row);
		PyList_Append(self->rows, row);
		self->nums ++;
	}

	self->readerPktPtr += pktlen;
	self->readerPktPtr = self->readerReadPtr;
	if (PyErr_Occurred()) {
		PyErr_Format(PyExc_ValueError, "Parse packet.");
		return 0;
	}
	return self->readerWritePtr - self->readerReadPtr;
}

PyObject *Con_isConnected(Con *self, PyObject *args) {
	if (self->sock) {
		Py_RETURN_TRUE;
	}
	self->tid = 0;
	Py_RETURN_FALSE;
}

static PyObject *Con_Connect(Con *self, PyObject *args) {
	/*
	 Args: Con conn, const char *_host, int _port, const char *_username, const char *_password, const char *_database, int _autoCommit, const char *_charset*/
	ulong i, len;
	UINT1 *pos;
	char *pstrCharset = NULL;

	if (!PyArg_ParseTuple(args, "sisss|bsb", &self->host, &self->port,
			&self->user, &self->pswd, &self->db, &self->ac, &pstrCharset))
		return -1;
	self->ac = (self->ac) ? 1 : 0;
	self->host = self->host ? self->host : "localhost";
	self->user = self->user ? self->user : "";
	self->pswd = self->pswd ? self->pswd : "";
	self->port = self->port ? self->port : 3306;
	if (pstrCharset) {
		if (strcmp(pstrCharset, "utf8") == 0) {
			self->charset = MCS_utf8_general_ci;
			self->PFN_PyUnicode_Encode = PyUnicode_EncodeUTF8;
		} else if (strcmp(pstrCharset, "latin1") == 0) {
			self->charset = MCS_latin1_general_ci;
			self->PFN_PyUnicode_Encode = PyUnicode_EncodeLatin1;
		} else if (strcmp(pstrCharset, "ascii") == 0) {
			self->charset = MCS_ascii_general_ci;
			self->PFN_PyUnicode_Encode = PyUnicode_EncodeASCII;
		} else if (strcmp(pstrCharset, "utf8bin") == 0) {
			self->charset = MCS_utf8_bin;
			self->PFN_PyUnicode_Encode = PyUnicode_DecodeUTF8;
		} else if (strcmp(pstrCharset, "bin") == 0) {
			self->charset = MCS_binary;
			self->PFN_PyUnicode_Encode = PyString_FromStringAndSize;
		} else {
			return PyErr_Format(PyExc_ValueError,
					"Unsupported character set '%s' specified", pstrCharset);
		}
	} else {
		self->charset = MCS_utf8_general_ci;
		self->PFN_PyUnicode_Encode = PyUnicode_EncodeUTF8;
	}

	if (self->sock)
		return PyErr_Format(PyExc_ValueError, "Already connected: TID:%d",
				self->tid);

	if (!(self->sock = API_getSocket())
			|| !API_connectSocket(self->sock, self->host, self->port)) {
		self->pid--;
		return API_error(self, "connect");
	}

	if (!self->readerStartPtr || !self->readerEndPtr
			|| self->readerReadPtr == self->readerWritePtr)
		readerReset(self);

	self->readerWritePtr = self->readerReadPtr = self->readerPktPtr =self->readerStartPtr;
	while(self->readerEndPtr -self->readerPktPtr <MY_HEADER_SIZE){
		len =self->readerEndPtr -self->readerStartPtr;
		if(len<=0){
			len=MY_BUFFER_SIZE;
		}else len =len<<1;
		assert(0<len&&len<=MY_BUFFER_MAX);
		long RSLen,PRLen, WPLen;
		RSLen=self->readerReadPtr -self->readerStartPtr;
		PRLen=self->readerPktPtr  -self->readerReadPtr;
		WPLen=self->readerWritePtr-self->readerPktPtr;
		MyRealloc(self->readerStartPtr,len);
		self->readerEndPtr  =self->readerStartPtr +len;
		self->readerReadPtr =self->readerStartPtr +RSLen;
		self->readerPktPtr  =self->readerReadPtr  +PRLen;
		self->readerWritePtr=self->readerPktPtr   +WPLen;
	};
	while (self->readerWritePtr -self->readerPktPtr <MY_HEADER_SIZE){
		len =API_recvSocket(self->sock, self->readerWritePtr, self->readerEndPtr-self->readerWritePtr);
		if(len<= 0L){
			break;
		}else self->readerWritePtr +=len;
	}assert(self->readerWritePtr -self->readerPktPtr >=MY_HEADER_SIZE);

	pos =self->readerPktPtr;
	i=len=pos[0] | pos[1]<<8 | pos[2]<<16;
	self->nid =pos[3];
	self->readerReadPtr=self->readerPktPtr =pos =pos +MY_HEADER_SIZE;
	while(self->readerEndPtr -self->readerPktPtr <i){
		len =self->readerEndPtr -self->readerStartPtr;
		if(len<=0){
			len=MY_BUFFER_SIZE;
		}else len =len<<1;
		assert(0<len&&len<=MY_BUFFER_MAX);
		long RSLen,PRLen, WPLen;
		RSLen=self->readerReadPtr -self->readerStartPtr;
		PRLen=self->readerPktPtr  -self->readerReadPtr;
		WPLen=self->readerWritePtr-self->readerPktPtr;
		MyRealloc(self->readerStartPtr,len);
		self->readerEndPtr  =self->readerStartPtr +len;
		self->readerReadPtr =self->readerStartPtr +RSLen;
		self->readerPktPtr  =self->readerReadPtr  +PRLen;
		self->readerWritePtr=self->readerPktPtr   +WPLen;
	};
	while (self->readerWritePtr -self->readerPktPtr <i){
		len =API_recvSocket(self->sock, self->readerWritePtr, self->readerEndPtr-self->readerWritePtr);
		if(len<= 0L){
			break;
		}else self->readerWritePtr +=len;
	}assert(self->readerWritePtr -self->readerPktPtr>=i);
	self->readerPktPtr =pos +i;
	if(i<64){
		self->pid--;
		return API_error(self, "packet receiving");
	}

	len=i;
	self->nid =pos[3];
	self->ver = readerUINT1(self);
	if (self->ver == 0xff) {
		THROW("Too many connections reported by server");
		return false;
	}
	if (self->ver != MY_PROTOCOL_VERSION) {
		THROW(
				"Protocol version expect:%0x, got(%0x)\n", MY_PROTOCOL_VERSION, self->ver);
		return false;
	}
	self->serverVersion = readerNTString(self);
	self->cid = readerUINT4(self);
	for (i = 0; i < MY_SCRAMBLE_LENGTH_323; i++, self->readerReadPtr++)
		self->scramble[i] = *self->readerReadPtr;
	self->scramble[MY_SCRAMBLE_LENGTH_323] = *(self->readerReadPtr++);

	i=len;
	self->serverCaps = readerUINT2(self);
	if (!(self->serverCaps & MCP_PROTOCOL_41)) {
		THROW("Authentication < 4.1 not supported");
		return false;
	}
	UINT1 serverLang = readerUINT1(self);
	self->serverStatus = readerUINT2(self);
	self->serverCaps |= readerUINT2(self) << 16;
	len = readerUINT1(self);
	if (len < 13 + MY_SCRAMBLE_LENGTH_323)
		len = 13;
	readerBytes(self, 10);

	for (i = MY_SCRAMBLE_LENGTH_323; i <= len; ++i, ++self->readerReadPtr)
		self->scramble[i] = *self->readerReadPtr;

	self->readerReadPtr = self->readerPktPtr;
	assert(self->readerPktPtr == self->readerWritePtr);

	self->clientFlag = self->serverCaps;
	self->clientFlag &= ~MCP_COMPRESS;
	self->clientFlag &= ~MCP_NO_SCHEMA;
	self->clientFlag &= ~MCP_SSL;
	self->clientFlag |= MCP_MULTI_STATEMENTS;
	self->clientFlag |= MCP_MULTI_RESULTS;
	self->clientFlag |= MCP_CONNECT_WITH_DB;
/*
#ifdef DEBUG
	fprintf(stderr,"host: %s:%u  user: %s  pswd:%s  db: %s  autocommit: %01u  flag: %06x  caps: %04x  blocking: %u\n\n",
			self->host ? self->host : "(Null)", self->port,
			self->user ? self->user : "(Null)", self->pswd ? self->pswd : "(Null)",
			self->db ? self->db : "(Null)", (UINT4)self->ac, self->clientFlag, self->serverCaps, self->blocking);
#endif
 */
	writerReset(self);
	writerINT4(self, self->clientFlag);
	writerINT4(self, MY_BUFFER_SIZE);
	if (self->charset != MCS_UNDEFINED) {
		writerINT1(self, (UINT1)self->charset);
	} else {
		writerINT1(self, self->serverLang);
	}
	for (i = 0; i < 23; i++)
		writerINT1(self, 0);

	if (self->user) {
		writerNTString(self, self->user);
	} else
		writerINT1(self, 0x0);

	if (self->pswd && self->pswd[0]) {
		writerINT1(self, MY_SHA1_HASH_SIZE);
		UINT8 token[MY_SHA1_HASH_SIZE + 1];
		token[MY_SHA1_HASH_SIZE] = 0;
		scramble_password(token, self->scramble, self->pswd);
		writerBytes(self, token, MY_SHA1_HASH_SIZE);
	} else
		writerINT1(self, 0x0);
	if (self->serverCaps & MCP_CONNECT_WITH_DB && self->db) {
		writerNTString(self, self->db);
	} else
		writerINT1(self, 0x0);
	writerFinalize(self, 1);
	API_sendSocket(self->sock, self->writerReadPtr, self->writerWritePtr - self->writerReadPtr);
	self->readerWritePtr = self->readerReadPtr = self->readerPktPtr =self->readerStartPtr;
	while (self->readerWritePtr -self->readerPktPtr <MY_HEADER_SIZE){
		len =API_recvSocket(self->sock, self->readerWritePtr, self->readerEndPtr-self->readerWritePtr);
		if(len<= 0L){
			break;
		}else self->readerWritePtr +=len;
	}assert(self->readerWritePtr -self->readerPktPtr >=MY_HEADER_SIZE);
	pos =self->readerPktPtr;
	i=len=pos[0] | pos[1]<<8 | pos[2]<<16;
	self->nid =pos[3];
	if(pos[4] != 0x0){
		self->pid--;
		return API_error(self, "packet receiving");
	}
	self->readerWritePtr = self->readerReadPtr = self->readerPktPtr =self->readerStartPtr;


	char strTemp[256 + 1];
	if (self->ac) {
		len =snprintf(strTemp, 256,
						"SET AUTOCOMMIT=1,time_zone='+0:00',sql_mode='TRADITIONAL',character_set_client='binary',character_set_results='binary'");
	} else {
		len =snprintf(strTemp, 256,
						"SET AUTOCOMMIT=0,time_zone='+0:00',sql_mode='TRADITIONAL',character_set_client='binary',character_set_results='binary'");
	}
	writerReset(self);
	writerINT1(self, COM_QUERY);
	writerBytes(self, strTemp, len);
	writerFinalize(self, 0);
	API_sendSocket(self->sock, self->writerReadPtr,self->writerWritePtr - self->writerReadPtr);
	self->readerWritePtr = self->readerReadPtr = self->readerPktPtr =self->readerStartPtr;
	while (self->readerWritePtr -self->readerPktPtr <MY_HEADER_SIZE){
		len =API_recvSocket(self->sock, self->readerWritePtr, self->readerEndPtr-self->readerWritePtr);
		if(len<= 0L){
			break;
		}else self->readerWritePtr +=len;
	}assert(self->readerWritePtr -self->readerPktPtr >=MY_HEADER_SIZE);
	pos =self->readerPktPtr;
	i=len=pos[0] | pos[1]<<8 | pos[2]<<16;
	self->nid =pos[3];
	if(pos[4] != 0x0){
		self->pid--;
		return API_error(self, "packet receiving");
	}
	self->readerWritePtr = self->readerReadPtr = self->readerPktPtr =self->readerStartPtr;
	self->writerWritePtr = self->writerReadPtr =self->writerStartPtr;
	return self;
}

int AppendAndEscapeString(char *buffStart, char *buffEnd, const char *strStart,
		const char *strEnd, int quote) {
	//{'\0': '\\0', '\n': '\\n', '\r': '\\r', '\\': '\\\\', "'": "\\'", '"': '\\"', '\x1a': '\\Z'}):
	char *buffOffset = buffStart;

	if (quote) {
		(*buffOffset++) = '\'';
	}

	while (strStart < strEnd) {
		switch (*strStart) {
		case '\0': // NULL
			(*buffOffset++) = '\\';
			(*buffOffset++) = '0';
			break;
		case '\n': // LF
			(*buffOffset++) = '\\';
			(*buffOffset++) = 'n';
			break;
		case '\r': // CR
			(*buffOffset++) = '\\';
			(*buffOffset++) = 'r';
			break;
		case '\\': // BACKSLASH
			(*buffOffset++) = '\\';
			(*buffOffset++) = '\\';
			break;
		case '\'': // SINGLE QUOTE
			(*buffOffset++) = '\\';
			(*buffOffset++) = '\'';
			break;
		case '\"': // DOUBLE QUOTE
			(*buffOffset++) = '\\';
			(*buffOffset++) = '\"';
			break;
		case '\x1a': // SUBSTITUTE CONTROL CHARACTER
			(*buffOffset++) = '\\';
			(*buffOffset++) = 'Z';
			break;

		default:
			(*buffOffset++) = (*strStart);
			break;
		}

		strStart++;
	}

	if (quote) {
		(*buffOffset++) = '\'';
	}

	return (int) (buffOffset - buffStart);
}

int AppendEscapedArg(Con *self, char *start, char *end, PyObject *obj) {
	int ret;
	PyObject *strobj;

	/*
	 FIXME: Surround strings with '' could be performed in this function to avoid extra logic in AppendAndEscapeString */
	if (PyString_Check(obj)) {
		return AppendAndEscapeString(start, end, PyString_AS_STRING(obj),
				PyString_AS_STRING(obj) + PyString_GET_SIZE(obj), true);
	} else if (PyUnicode_Check(obj)) {
		strobj = self->PFN_PyUnicode_Encode(PyUnicode_AS_UNICODE(obj),
				PyUnicode_GET_SIZE(obj), NULL);

		if (strobj == NULL) {
			if (PyErr_Occurred()) {
				return -1;
			}

			PyErr_SetObject(PyExc_ValueError, obj);
			return -1;
		}

		ret = AppendAndEscapeString(start, end, PyString_AS_STRING(strobj),
				PyString_AS_STRING(strobj) + PyString_GET_SIZE(strobj), true);
		Py_DECREF(strobj);

		return ret;
	} else if (obj == Py_None) {
		(*start++) = 'n';
		(*start++) = 'u';
		(*start++) = 'l';
		(*start++) = 'l';
		return 4;
	} else if (PyDateTime_Check(obj)) {
		int len = sprintf(start, "'%04d-%02d-%02d %02d:%02d:%02d'",
				PyDateTime_GET_YEAR(obj), PyDateTime_GET_MONTH(obj),
				PyDateTime_GET_DAY(obj), PyDateTime_DATE_GET_HOUR(obj),
				PyDateTime_DATE_GET_MINUTE(obj),
				PyDateTime_DATE_GET_SECOND(obj));

		return len;
	} else if (PyDate_Check(obj)) {
		int len = sprintf(start, "'%04d:%02d:%02d'", PyDateTime_GET_YEAR(obj),
				PyDateTime_GET_MONTH(obj), PyDateTime_GET_DAY(obj));

		return len;
	}

	//FIXME: Might possible to avoid this?
	strobj = PyObject_Str(obj);
	ret = AppendAndEscapeString(start, end, PyString_AS_STRING(strobj),
			PyString_AS_STRING(strobj) + PyString_GET_SIZE(strobj), false);
	Py_DECREF(strobj);
	return ret;
}

PyObject *EscapeQueryArguments(Con *self, PyObject *inQuery, PyObject *iterable) {
	size_t cbOutQuery = 0;
	char *obuffer;
	char *optr;
	char *iptr;
	int heap = 0;
	int appendLen;
	PyObject *retobj;
	PyObject *iterator;
	PyObject *arg;

	// Estimate output length

	cbOutQuery += PyString_GET_SIZE(inQuery);

	iterator = PyObject_GetIter(iterable);

	while ((arg = PyIter_Next(iterator))) {
		// Quotes;
		cbOutQuery += 2;

		// Worst case escape and utf-8
		if (PyString_Check(arg))
			cbOutQuery += (PyString_GET_SIZE(arg) * 2);
		else if (PyUnicode_Check(arg))
			cbOutQuery += (PyUnicode_GET_SIZE(arg) * 6);
		else
			cbOutQuery += 64;

		Py_DECREF(arg);
	}

	Py_DECREF(iterator);

	if (cbOutQuery > (1024 * 64)) {
		/*
		 FIXME: Allocate a PyString and resize it just like the Python code does it */
		obuffer = (char *) PyObject_Malloc(cbOutQuery);
		heap = 1;
	} else {
		obuffer = (char *) alloca(cbOutQuery);
	}

	optr = obuffer;
	iptr = PyString_AS_STRING(inQuery);

	iterator = PyObject_GetIter(iterable);

	while (1) {
		switch (*iptr) {
		case '\0':
			goto END_PARSE;

		case '%':

			iptr++;

			if (*iptr != 's' && *iptr != '%') {
				Py_DECREF(iterator);
				if (heap)
					PyObject_Free(obuffer);
				return PyErr_Format(PyExc_ValueError,
						"Found character %c expected %%", *iptr);
			}

			if (*iptr == '%') {
				*(optr++) = *(iptr)++;
				break;
			}

			iptr++;

			arg = PyIter_Next(iterator);

			if (arg == NULL) {
				Py_DECREF(iterator);
				if (heap)
					PyObject_Free(obuffer);
				return PyErr_Format(PyExc_ValueError,
						"Unexpected end of iterator found");
			}

			appendLen = AppendEscapedArg(self, optr, obuffer + cbOutQuery, arg);
			Py_DECREF(arg);

			if (appendLen == -1) {
				Py_DECREF(iterator);
				if (heap)
					PyObject_Free(obuffer);
				return NULL;
			}

			optr += appendLen;

			break;

		default:
			*(optr++) = *(iptr)++;
			break;
		}
	}

	END_PARSE: Py_DECREF(iterator);

	retobj = PyString_FromStringAndSize(obuffer, (optr - obuffer));

	if (heap) {
		PyObject_Free(obuffer);
	}

	return retobj;
}

PyObject *Con_Query(Con *self, PyObject *args) {
	int retMore = 0;
	PyObject *inQuery = NULL;
	PyObject *iterable = NULL;
	PyObject *escapedQuery = NULL;
	PyObject *query = NULL;

	if (!self->sock)
		return PyErr_Format(PyExc_RuntimeError, "Not connected");
	if (!PyArg_ParseTuple(args, "O|O", &inQuery, &iterable)) {
		return NULL;
	}

	if (iterable) {
		PyObject *iterator = PyObject_GetIter(iterable);
		if (iterator == NULL) {
			PyErr_Clear();
			return PyErr_Format(PyExc_TypeError, "Expected iterable");
		}
		Py_DECREF(iterator);
	}
	if (!PyString_Check(inQuery)) {
		if (!PyUnicode_Check(inQuery)) {
			return PyErr_Format(PyExc_TypeError,
					"Query argument must be either String or Unicode");
		}
		query = self->PFN_PyUnicode_Encode(PyUnicode_AS_UNICODE(inQuery),
				PyUnicode_GET_SIZE(inQuery), NULL);
		if (query == NULL) {
			if (!PyErr_Occurred()) {
				PyErr_SetObject(PyExc_ValueError, query);
				return NULL;
			}
			return NULL;
		}
	} else {
		query = inQuery;
		Py_INCREF(query);
	}

	if (iterable) {
		escapedQuery = EscapeQueryArguments(self, query, iterable);
		Py_DECREF(query);

		if (escapedQuery == NULL) {
			if (!PyErr_Occurred()) {
				return PyErr_Format(PyExc_RuntimeError,
						"Exception not set in EscapeQueryArguments chain");
			}
			return NULL;
		}
	} else {
		escapedQuery = query;
	}

	writerReset(self);
	writerINT1(self, COM_QUERY);
	writerBytes(self, PyString_AS_STRING(escapedQuery),
			PyString_GET_SIZE(escapedQuery));
	writerFinalize(self, 0);
	API_sendSocket(self->sock, self->writerReadPtr, self->writerWritePtr - self->writerReadPtr);
/*
#ifdef DEBUG
	pbuf(stderr, self->writerReadPtr, self->writerWritePtr -self->writerReadPtr, 16);
	fprintf(stderr, "\nS: %p    R: %p    P: %p    W: %p    E: %p\n",self->readerStartPtr, self->readerReadPtr,
			self->readerPktPtr, self->readerWritePtr, self->readerEndPtr);
#endif
*/
	self->writerWritePtr = self->writerReadPtr =self->writerStartPtr;
	self->readerWritePtr = self->readerReadPtr = self->readerPktPtr =self->readerStartPtr;
	Con_PacketRecv(self, 0);

	if (PyErr_Occurred()) {
		PyErr_Print();
		Py_INCREF(Py_None);
		return Py_None;
	}
	Py_INCREF(Py_None);
	return Py_None;

	/*
	 if ((*PyString_AS_STRING(escapedQuery)) == ' ')retMore = 1;
	 //  ret = Con_Query(self, PyString_AS_STRING(escapedQuery), PyString_GET_SIZE(escapedQuery), retMore);

	 Py_DECREF(escapedQuery);

	 if (ret == NULL)
	 {
	 return API_error(self, "query result");
	 }

	 if(PyTuple_Check(ret))return ret; // it's a OK packet, return (affectedRows, insertID, ... ), see above API_resultOK();

	 if(retMore){
	 PyObject *tuple = PyTuple_New(2);
	 PyTuple_SET_ITEM(tuple, 0, ret->fields);
	 PyTuple_SET_ITEM(tuple, 1, ret->rows);
	 return tuple;
	 }else return ret->rows;
	 */
}

static PyMethodDef Con_methods[] =
		{
				{ "connect", (PyCFunction) Con_Connect, METH_VARARGS,
						"Connects to database server. Arguments: host, port, username, password, database, autocommit, charset" },
				{ "query", (PyCFunction) Con_Query, METH_VARARGS,
						"Performs a query. Arguments: query, arguments to escape" },
				{ "close", (PyCFunction) Con_Clear, METH_NOARGS,
						"Closes connection" },
//  {"ping", (PyCFunction) Con_ping, METH_NOARGS, "Check connection status"},
				{ "isConnected", (PyCFunction) Con_isConnected, METH_NOARGS,
						"Check connection status" },
//  {"setTimeout", (PyCFunction) Con_setTimeout, METH_VARARGS, "Sets connection timeout in seconds"},
//  {"setTxBufferSize", (PyCFunction) Con_setTxBufferSize, METH_VARARGS, "Sets connection timeout in seconds"},
//  {"setRxBufferSize", (PyCFunction) Con_setRxBufferSize, METH_VARARGS, "Sets connection timeout in seconds"},
				{ NULL } };
static PyMemberDef Con_members[] = {

{ "Error", T_OBJECT, offsetof(Con, Error), READONLY },
{ "SQLError", T_OBJECT, offsetof(Con, SQLError), READONLY },
{ "tid", T_INT, offsetof(Con, tid), READONLY, "Server side thread id" },
{ "sock", T_OBJECT, offsetof(Con, sock), 1, "Server side Python Socket" },
{ "rows", T_OBJECT, offsetof(Con, rows), 1, "Query result rows" },
{ "fields",T_OBJECT, offsetof(Con, fields), 1, "Query result fields" },
{ "host", T_STRING, offsetof(Con,host), READONLY, "Server host name" },
{ "username", T_STRING, offsetof(Con, user), READONLY, "user name" },
{ "password", T_STRING, offsetof(Con, pswd), READONLY, "password" },
{"port", T_INT, offsetof(Con, port), READONLY, "Server side port" },
		{ NULL } };

static PyTypeObject ConType = {
	PyObject_HEAD_INIT(NULL)
	0, /* ob_size        */
	"amysql.Con", /* tp_name        */
	sizeof(Con), /* tp_basicsize   */
	0,             /* tp_itemsize    */
	Con_Destructor, /* tp_dealloc     */
	0, /* tp_print       */
	0, /* tp_getattr     */
	0, /* tp_setattr     */
	0, /* tp_compare     */
	0, /* tp_repr        */
	0, /* tp_as_number   */
	0, /* tp_as_sequence */
	0, /* tp_as_mapping  */
	0, /* tp_hash        */
	0, /* tp_call        */
	0, /* tp_str         */
	0, /* tp_getattro    */
	0, /* tp_setattro    */
	0, /* tp_as_buffer   */
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC, /* tp_flags       */
	"", /* tp_doc         */
	Con_Traverse, /* tp_traverse       */
	Con_Clear, /* tp_clear          */
	0, /* tp_richcompare    */
	0, /* tp_weaklistoffset */
	0, /* tp_iter           */
	0, /* tp_iternext       */
	Con_methods, /* tp_methods        */
	Con_members, /* tp_members        */
	0, /* tp_getset         */
	0, /* tp_base           */
	0, /* tp_dict           */
	0, /* tp_descr_get      */
	0, /* tp_descr_set      */
	0, /* tp_dictoffset     */
	(initproc)Con_Constructor, /* tp_init           */
    0,                         /* tp_alloc */
	Con_New,                 /* tp_new */
};

static PyMethodDef methods[] = { { NULL, NULL, 0, NULL } /* Sentinel */
};

PyMODINIT_FUNC initamysql(void) {
	PyObject* m;
	PyObject *dict;
	PyDateTime_IMPORT;

	m = Py_InitModule3("amysql", methods, "");
	if (m == NULL)
		return;

	dict = PyModule_GetDict(m);

	ConType.tp_new = PyType_GenericNew;
	if (PyType_Ready(&ConType) < 0)
		return;
	Py_INCREF(&ConType);
	PyModule_AddObject(m, "Con", (PyObject *) &ConType);

	amysql_Error = PyErr_NewException("amysql.Error", PyExc_Error,
			NULL);
	amysql_SQLError = PyErr_NewException("amysql.SQLError", amysql_Error, NULL);

	PyDict_SetItemString(dict, "Error", amysql_Error);
	PyDict_SetItemString(dict, "SQLError", amysql_SQLError);

	if (sockclass == NULL) {
		if(sockmodule == NULL){
			sockmodule = PyImport_ImportModule("socket");
			if (sockmodule == NULL){fprintf(stderr, "Error importing Python standard socket module\n");exit(-1);}
		}
		sockclass = PyObject_GetAttrString(sockmodule, "socket");
		if (!sockclass ||!PyType_Check(sockclass) ||!PyCallable_Check(sockclass)){fprintf(stderr, "Error get 'socket.socket' method\n");exit(-1);}
	}
}


#endif




