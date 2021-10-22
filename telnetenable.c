/*
  This program is a re-implementation of the telnet console enabler utility
  for use with Netgear wireless routers.
  
  The original Netgear Windows binary version of this tool is available here:
  http://www.netgear.co.kr/Support/Product/FileInfo.asp?IDXNo=155
  
  Per DMCA 17 U.S.C. §1201(f)(1)-(2), the original Netgear executable was
  reverse engineered to enable interoperability with other operating systems
  not supported by the original windows-only tool (MacOS, Linux, etc).

  Currently his program implements the only the signing and encryption parts
  of Netgear telnet-enable algorithm, it does not provide the network socket
  support, but can trivially be used with 'netcat' or other tools capable of
  sending the output of this program to telnet port 23 on the router.
  

	Netgear Router - Console Telnet Enable Utility 
	Release 0.1 : 25th June 2006
	Copyright (C) 2006, yoshac @ member.fsf.org

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along
	with this program; if not, write to the Free Software Foundation, Inc.,
	51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


  The RSA MD5 and Blowfish implementations are provided under LGPL from
  http://www.opentom.org/Mkttimage 
 
  Added a socket layer by haiyue @ Delta Networks Inc. 2008-02-25
  Hope yoshac NOT mind the stupid modification :)
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/md5.h>

#include "blowfish.h"

struct PAYLOAD
{
	char signature[0x10];
	char mac[0x10];
	char username[0x10];
	char password[0x40];
	char reserved[0x40];
};

#define __BIG_ENDIAN__	1

static void hash_data(char *mess, char *hash)
{
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned md_len;

	OpenSSL_add_all_digests();
	md = EVP_sha256();
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, mess, strlen(mess));
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);
	EVP_cleanup();

	for (int i = 0; i < md_len; ++i)
		sprintf(&hash[2 * i], "%02X", md_value[i]);
}

static int open_telnet(char *ip)
{
	int fd, on = 1;
	struct sockaddr_in sa;
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(23);
	inet_pton(AF_INET, ip, &(sa.sin_addr));
	
	if (connect(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0)
		return -1;

	return fd;
}

/****************************************************************/

int GetOutputLength(unsigned long lInputLong)
{
	unsigned long lVal = lInputLong % 8;

	if (lVal!=0)
		return lInputLong+8-lVal;
	else
		return lInputLong;
}

#define GET32U(p, x) do { \
			x = p[3]; \
			x = (x << 8) |p[2]; \
			x = (x << 8) |p[1]; \
			x = (x << 8) |p[0]; \
		} while(0)
	
#define PUT32U(p, x) do { \
			p[0] = (x) & 0xFF; \
			p[1] = (x >> 8) & 0xFF; \
			p[2] = (x >> 16) & 0xFF; \
			p[3] = (x >> 24) & 0xFF; \
		} while(0)
	
int EncodeString(void *ctx, char *pInput,char *pOutput, int lSize)
{
	int lCount;
	int lOutSize;

#if __BIG_ENDIAN__
	unsigned char *pi = (unsigned char *)pInput;
	unsigned char *po = (unsigned char *)pOutput;
#else
	int i = 0;
#endif

	lOutSize = GetOutputLength(lSize);
	lCount=0;
	while (lCount<lOutSize)
	{
	#if __BIG_ENDIAN__	
		uint32 xl, xr;

		GET32U(pi, xl); pi +=4;
		GET32U(pi, xr); pi +=4;
		Blowfish_Encrypt(ctx, &xl, &xr);
		PUT32U(po, xl); po += 4;
		PUT32U(po, xr); po += 4;
		
		lCount += 8;
	#else
		char *pi=pInput;
		char *po=pOutput;
		for (i=0; i<8; i++)
			*po++=*pi++;
		Blowfish_Encrypt(ctx, (uint32 *)pOutput, (uint32 *)(pOutput+4));
		pInput+=8;
		pOutput+=8;
		lCount+=8;
	#endif
	}

	return lCount;
}

int fill_payload(char *p, char *argv[])
{
	int secret_len;
	int encoded_len;
	MD5_CTX MD;
	BLOWFISH_CTX BF;
	struct PAYLOAD payload;
	char username[0x10] = "admin";
	char password[0x40];
	char mac[0x10], MD5_key[0x11];
	char secret_key[0x80];

	hash_data(argv[3], password);
	char *tok = strtok(argv[2], ":-");
	while (tok) {
		for (int i = 0; i < strlen(tok); ++i)
			tok[i] = toupper(tok[i]);
		strcat(mac, tok);
		tok = strtok(NULL, ":-");
	}
	
	memset(&payload, 0, sizeof(payload));
	memcpy(payload.mac, mac, 0x10);
	memcpy(payload.username, username, 0x10);
	memcpy(payload.password, password, 0x40);

	MD5_Init(&MD);
	MD5_Update(&MD, (unsigned char *)payload.mac, 0x70);
	MD5_Final((unsigned char *)MD5_key, &MD);

#if 1
	memcpy(payload.signature, MD5_key, 0x10);
#else
	MD5_key[0x10] = '\0'; /* ?? */
	strcpy(payload.signature, MD5_key);
	strcat(payload.signature, mac);
#endif

	secret_len = sprintf(secret_key, "AMBIT_TELNET_ENABLE+%s", password);
	Blowfish_Init(&BF, (unsigned char *)secret_key, secret_len);	
	encoded_len = EncodeString(&BF, (char*)&payload, p, 0xB0);

	return encoded_len;
}

int main(int argc, char *argv[])
{
	int fd, datasize, r;
	char output_buf[512] = {0};

	if (argc != 4) {
		puts("telnetenable for R9000");
		printf("Usage: %s <ip> <mac> <password>\n", argv[0]);
		return 1;
	}

	datasize = fill_payload(output_buf, argv);
	fd = open_telnet(argv[1]);
	r = write(fd, output_buf, datasize);
	close(fd);

	if (r < 0)
	{
		printf("%s\n", strerror(r));
		return 1;
	}
	else
	{
		printf("%d bytes payload sent.\n", r);
		puts("If the data is correct, R9000 will open telnet.");
		return 0;
	}
}

