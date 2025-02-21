#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#endif

#include "dat.h"
#include "fns.h"

static inline int rsize(SOCKET fd);

int
sclunk(SOCKET fd, uint32_t fid)
{
  uint32_t total_size = 7 + 4;
  unsigned char msg[total_size];
  int offset;
  Header hdr = { total_size, Tclunk, 0 };

  offset = packheader(&hdr, msg);
  pack32(msg, fid, &offset);

  return send(fd, (char *)msg, total_size, 0);
}

int
rclunk(SOCKET fd, Error *err)
{
  uint32_t size, nbytes;
  unsigned char msg[8192];

  size = rsize(fd);
  if (size == 0) {
    perror("rclunk size");
    return -1;
  }
  else if(size > sizeof msg) {
    fprintf(stderr, "message too large: %u", size);
    return -1;
  }

  nbytes = recv(fd, (char *)msg + 4, size - 4, 0);
  if(nbytes != size - 4) {
    perror("incomplete message received");
    return -1;
  }

  if(msg[4] == Rerror) {
    err->elen = *(uint16_t *)(msg + 7);
    if(err->elen > size - 9) {
      fprintf(stderr, "invalid error message size");
      return -1;
    }

    err->ename = malloc(err->elen + 1);
    if(err->ename == NULL) {
      perror("rclunk malloc");
      return -1;
    }
    memcpy(err->ename, msg + 9, err->elen);
    err->ename[err->elen] = 0;
    return 0;
  }

  if(msg[4] != Rclunk) {
    fprintf(stderr, "unexpected message type: %u", msg[4]);
    return -1;
  }

  return 0;
}

int
sattach(SOCKET fd, Attach *a)
{
  unsigned char *msg;
  int offset, nbytes;

  printf("Sending attach: size=%u, type=%u, tag=%u, fid=%u, afid=%u, uname=%s, "
         "aname=%s\n",
         a->hdr.size, a->hdr.type, a->hdr.tag, a->fid, a->afid, a->uname, a->aname);
  if((msg = malloc(a->hdr.size)) == NULL) {
    perror("sattach malloc");
    return -1;
  }

  offset = packheader(&a->hdr, msg);
  pack32(msg, a->fid, &offset);
  pack32(msg, a->afid, &offset);
  packstr(msg, a->uname, &offset);
  packstr(msg, a->aname, &offset);

  nbytes = send(fd, (char *)msg, a->hdr.size, 0);
  printf("Sent %d bytes, offset: %d\n", nbytes, offset);
  free(msg);
  return nbytes;
}

int
rattach(SOCKET fd, Qid *qid, Error *err)
{
  uint32_t size, nbytes;
  unsigned char msg[8192];
  int offset;

  puts("rsize");
  size = rsize(fd);
  if (size == 0) {
    perror("rattach size");
    return -1;
  }
  else if(size > sizeof msg) {
    fprintf(stderr, "message too large: %u", size);
    return -1;
  }

  /* get rest of message */
  puts("rest");
  nbytes = recv(fd, (char *)msg + 4, size - 4, 0);
  if(nbytes != size - 4) {
    perror("incomplete message received");
    return -1;
  }

  /* check message type */
  if(msg[4] == Rerror) {
    err->elen = *(uint16_t *)(msg + 7);
    if(err->elen > size - 9) {
      fprintf(stderr, "invalid error message size");
      return -1;
    }

    err->ename = malloc(err->elen + 1);
    if(err->ename == NULL) {
      perror("rattach malloc");
      return -1;
    }
    memcpy(err->ename, msg + 9, err->elen);
    err->ename[err->elen] = 0;
    return 0;
  }

  if(msg[4] != Rattach) {
    fprintf(stderr, "unexpected message type: %u", msg[4]);
    return -1;
  }

  /* unpack qid */
  offset = 7;
  qid->type = msg[offset];
  offset++;
  qid->vers = *(uint32_t *)(msg + offset);
  offset += 4;
  qid->path = *(uint64_t *)(msg + offset);

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
  printf("reading size\n");
  nbytes = recv(fd, (char *)msg, 4, 0);
  printf("read %d bytes\n", nbytes);
  if (nbytes != 4) {
    return 0;
  }

  return *(uint32_t *)msg;
}

int rver(SOCKET fd, Version *ver)
{
  uint32_t size, nbytes;
  unsigned char msg[8192];

  size = rsize(fd);
  if (size == 0) {
    perror("rver size");
    return -1;
  }
  else if(size > sizeof msg) {
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
	struct addrinfo hints;
	struct addrinfo *res;
	SOCKET fd;
	char *host;
	char port[6];
	int r;
	Version ver;
	Attach att;
  Qid qid;
  Error err;

#ifdef _WIN32
	WSADATA wsa;
	if(WSAStartup(MAKEWORD(2,2), &wsa) != 0){
		fprintf(stderr, "wsastartup failed\n");
		exit(1);
	}
#endif

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

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	r = getaddrinfo(host, port, &hints, &res);
	if(r != 0){
		fprintf(stderr, "getaddrinfo failed\n");
#ifdef _WIN32
		WSACleanup();
#endif
		exit(1);
	}

	fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if(fd == INVALID_SOCKET){
		fprintf(stderr, "socket failed\n");
		freeaddrinfo(res);
#ifdef _WIN32
		WSACleanup();
#endif
		exit(1);
	}

	if(connect(fd, res->ai_addr, res->ai_addrlen) == SOCKET_ERROR){
		fprintf(stderr, "connect failed\n");
		closesocket(fd);
		freeaddrinfo(res);
#ifdef _WIN32
		WSACleanup();
#endif
		exit(1);
	}

	freeaddrinfo(res);
	fprintf(stderr, "connected to %s:%s\n", host, port);
	if((r = sver(fd)) < 0) goto Exit;
  if((r = rver(fd, &ver)) < 0) goto Exit;

  printf("HEADER[ %u, %u, %u ] VERSION[ %u, %u, %s ]\n",
          ver.hdr.size, ver.hdr.type, ver.hdr.tag,
          ver.msize, ver.vlen, ver.version);

  fflush(stdout);

  att.hdr.size = 7 + 4 + 4 + 2 + 4 + 2 + 0;
  att.hdr.type = Tattach;
  att.hdr.tag = 0;
  att.fid = 0;
  att.afid = NOFID;
  att.ulen = sizeof "none";
  att.uname = "none";
  att.alen = 0;
  att.aname = "";

  err.elen = 0;
  err.ename = NULL;

  if((r = sattach(fd, &att)) < 0) goto Exit;
  if((r = rattach(fd, &qid, &err)) < 0) goto Exit;

  if(err.ename != NULL) {
    fprintf(stderr, "Rerror: %s\n", err.ename);
    r = -1;
    goto Exit;
  }
  printf("QID[ %u, %u, %llu ]", qid.type, qid.vers, qid.path);

  if((r = sclunk(fd, att.fid)) < 0) goto Exit;
  if((r = rclunk(fd, &err)) < 0) goto Exit;
  else printf("Received Rclunk\n");


  Exit:
	closesocket(fd);
#ifdef _WIN32
	WSACleanup();
#endif
	exit(r);
}
