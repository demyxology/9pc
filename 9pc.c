#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "dat.h"
#include "fns.h"

static inline int rsize(SOCKET fd);

int
sattach(SOCKET fd, Attach *a)
{
  uint32_t total_size = 6 + 4 + 4 + 2 + strlen(a->uname) + 2 + strlen(a->aname);
  unsigned char *msg;
  int offset, nbytes;

  if((msg = malloc(total_size)) == NULL) {
    perror("sattach malloc");
    return -1;
  }

  offset = packheader(&a->hdr, msg);
  pack32(msg, a->fid, &offset);
  pack32(msg, a->afid, &offset);
  packstr(msg, a->uname, &offset);
  packstr(msg, a->aname, &offset);

  nbytes = send(fd, (char *)msg, total_size, 0);
  free(msg);
  return nbytes;
}

int
rattach(SOCKET fd, Qid *qid)
{
  return 0;
}

int
sver(SOCKET fd)
{
  /* "9P2000" is 6 bytes */
  uint32_t total_size = 4 + 1 + 2 + 4 + 2 + 6;
  unsigned char msg[total_size];
  uint32_t msize = 8192;
  int offset;
  Header hdr = { total_size, Tversion, 0 };

  /* little endian */
  offset = packheader(&hdr, msg);
  pack32(msg, msize, &offset);
  packstr(msg, "9P2000", &offset);

  return send(fd, (char *)msg, total_size, 0);
}

static inline int
rsize(SOCKET fd)
{
  uint32_t nbytes;
  char msg[16];
  nbytes = recv(fd, (char *)msg, 4, 0);
  if (nbytes != 4) {
    perror("Failed to receive size");
    return 0;
  }

  return *(uint32_t *)msg;
}

int rver(SOCKET fd, Version *ver)
{
  uint32_t size, nbytes;
  unsigned char msg[8192];

  size = rsize(fd);
  if(size == 0) return 0;
  if(size > sizeof msg) {
    fprintf(stderr, "message too large: %u", size);
    return -1;
  }

  /* get rest of message */
  nbytes = recv(fd, (char *)msg + 4, size - 4, 0);
  if (nbytes != size - 4) {
    perror("incomplete message received");
    return -1;
  }

  /* unpack */
  ver->hdr.size = size;
  ver->hdr.type = msg[4];
  ver->hdr.tag = *(uint16_t *)(msg + 5);
  ver->msize = *(uint32_t *)(msg + 7);
  ver->vlen = *(uint16_t *)(msg + 11);
  memcpy(ver->version, msg + 13, ver->vlen);
  ver->version[ver->vlen] = 0;

  return 0;
}

int
main(int argc, char *argv[])
{
	WSADATA wsa;
	struct addrinfo hints;
	struct addrinfo *res;
	SOCKET fd;
	char *host;
	char port[6];
	int r;
  Version ver;
  Attach att;

	switch(argc){
	case 2:
		host = argv[1];
		sprintf(port, "%d", 564);
		break;
	case 3:
		host = argv[1];
		sprintf(port, "%s", argv[2]);
		break;
	default:
		fprintf(stderr, "usage: %s host [port]\n", argv[0]);
		exit(1);
	}

	if(WSAStartup(MAKEWORD(2,2), &wsa) != 0){
		fprintf(stderr, "wsastartup failed\n");
		exit(1);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	r = getaddrinfo(host, port, &hints, &res);
	if(r != 0){
		fprintf(stderr, "getaddrinfo failed\n");
		WSACleanup();
		exit(1);
	}

	fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if(fd == INVALID_SOCKET){
		fprintf(stderr, "socket failed\n");
		freeaddrinfo(res);
		WSACleanup();
		exit(1);
	}

	if(connect(fd, res->ai_addr, res->ai_addrlen) == SOCKET_ERROR){
		fprintf(stderr, "connect failed\n");
		closesocket(fd);
		freeaddrinfo(res);
		WSACleanup();
		exit(1);
	}

	freeaddrinfo(res);
	fprintf(stderr, "connected to %s:%s\n", host, port);
  if(sver(fd) > 0) {
    if(rver(fd, &ver) >= 0) {
      printf("HEADER[ %u, %u, %u ] VERSION[ %u, %u, %s ]", ver.hdr.size, ver.hdr.type, ver.hdr.tag,
             ver.msize, ver.vlen, ver.version);
      r = 0;
    } else {
      r = -1;
    }
  }

	closesocket(fd);
	WSACleanup();
	exit(r);
}
