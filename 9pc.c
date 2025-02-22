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
sstat(SOCKET fd, uint32_t fid)
{
  uint32_t total_size = 7 + 4;
  unsigned char msg[total_size];
  int offset;
  Header hdr = { total_size, Tstat, 0 };
  int nbytes;

  offset = 0;
  packheader(msg, &hdr, &offset);
  pack32(msg, fid, &offset);

  nbytes = send(fd, (char *)msg, total_size, 0);
  return nbytes;
}

int
rstat(SOCKET fd, Stat *stat, Error *err)
{
  uint32_t size, nbytes;
  unsigned char msg[8192];
  int offset;
  Header hdr;

  size = rsize(fd);
  if(size == 0) {
    perror("rstat size");
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

  offset = 0;
  unpackheader(msg, &hdr, &offset);

  if(hdr.type == Rerror) {
    unpackstr(msg, err->elen, err->ename, 256, &offset);
    return 0;
  }

  if(hdr.type != Rstat) {
    fprintf(stderr, "unexpected message type: %u", msg[4]);
    return -1;
  }

  unpack16(msg, &stat->size, &offset);
  unpack16(msg, &stat->type, &offset);
  unpack32(msg, &stat->dev, &offset);
  unpackqid(msg, &stat->qid, &offset);
  unpack32(msg, &stat->mode, &offset);
  unpack32(msg, &stat->atime, &offset);
  unpack32(msg, &stat->mtime, &offset);
  unpack64(msg, &stat->length, &offset);
  unpack16(msg, &stat->name, &offset);
  unpackstr(msg, stat->name, &offset);
  unpack16(msg, &stat->uid, &offset);
  unpackstr(msg, stat->uid, &offset);

  return 0;
}

int
sflush(SOCKET fd, uint16_t oldtag)
{
  uint32_t total_size = 7 + 2; /* header + tag */
  unsigned char msg[total_size];
  int offset;
  Header hdr = { total_size, Tflush, 0 };
  int nbytes;

  offset = 0;
  packheader(msg, &hdr, &offset);
  pack16(msg, oldtag, &offset);

  nbytes = send(fd, (char *)msg, total_size, 0);
  return nbytes;
}

int
rflush(SOCKET fd)
{
  uint32_t size, nbytes;
  unsigned char msg[8192];
  Header hdr;
  int offset;

  size = rsize(fd);
  if(size == 0) {
    perror("rflush size");
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

  offset = 0;
  unpackheader(msg, &hdr, &offset);

  if(hdr.type != Rflush) {
    fprintf(stderr, "unexpected message type: %u", msg[4]);
    return -1;
  }

  return 0;
}

int
swalk(SOCKET fd, uint32_t fid, uint32_t newfid, uint16_t nwname, char **wname)
{
  Header hdr;
  unsigned char *msg;
  int offset, nbytes;

  hdr.size = 4 + 1 + 2 + 4 + 4 + 2; /* not full size yet */
  hdr.tag = 0;
  hdr.type = Twalk;

  for(int i = 0; i < nwname; i++) {
    hdr.size += 2 + strlen(wname[i]); /* str length header + strlen */
  }

  msg = malloc(hdr.size);
  if (msg == NULL) {
    perror("swalk malloc");
    return -1;
  }

  offset = 0;
  packheader(msg, &hdr, &offset);
  pack32(msg, fid, &offset);
  pack32(msg, newfid, &offset);
  pack16(msg, nwname, &offset);

  for(int i = 0; i < nwname; i++) {
    packstr(msg, wname[i], &offset);
  }

  nbytes = send(fd, (char *)msg, hdr.size, 0);

  free(msg);

  return nbytes;
}

int
rwalk(SOCKET fd, Qid *qids, Error *err)
{
  uint16_t nwquid;
  uint32_t size, nbytes;
  unsigned char msg[8192];
  int offset;
  Header hdr;

  size = rsize(fd);
  if (size == 0) {
    perror("rwalk size");
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

  offset = 0;
  unpackheader(msg, &hdr, &offset);

  /* check message type */
  if(hdr.type == Rerror) {
    unpackstr(msg, err->elen, err->ename, 256, &offset);
    return 0;
  }

  if(hdr.type != Rwalk) {
    fprintf(stderr, "unexpected message type: %u", msg[4]);
    return -1;
  }

  unpack16(msg, &nwquid, &offset);
  if(nwquid > MAXWELEM) {
    fprintf(stderr, "too many qids: %u", nwquid);
    return -1;
  }

  for(int i = 0; i < nwquid; i++) {
    unpackqid(msg, qids + i, &offset);
  }

  return nwquid;
}

int
sclunk(SOCKET fd, uint32_t fid)
{
  uint32_t total_size = 7 + 4;
  unsigned char msg[total_size];
  int offset;
  Header hdr = { total_size, Tclunk, 0 };
  int nbytes;

  offset = 0;
  packheader(msg, &hdr, &offset);
  pack32(msg, fid, &offset);

  nbytes = send(fd, (char *)msg, total_size, 0);
  return nbytes;
}

int
rclunk(SOCKET fd, Error *err)
{
  uint32_t size, nbytes;
  unsigned char msg[8192];
  Header hdr;
  int offset;

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

  offset = 0;
  unpackheader(msg, &hdr, &offset);

  if(hdr.type == Rerror) {
    unpackstr(msg, err->elen, err->ename, 256, &offset);
    return 0;
  }

  if(hdr.type != Rclunk) {
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

  if((msg = malloc(a->hdr.size)) == NULL) {
    perror("sattach malloc");
    return -1;
  }

  offset = 0;
  packheader(msg, &a->hdr, &offset);
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
  Header hdr;

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
  nbytes = recv(fd, (char *)msg + 4, size - 4, 0);
  if(nbytes != size - 4) {
    perror("incomplete message received");
    return -1;
  }

  offset = 0;
  unpackheader(msg, &hdr, &offset);

  /* check message type */
  if(hdr.type == Rerror) {
    unpackstr(msg, err->elen, err->ename, 256, &offset);
    return 0;
  }

  if(hdr.type != Rattach) {
    fprintf(stderr, "unexpected message type: %u", msg[4]);
    return -1;
  }

  /* unpack qid */
  qid->type = msg[offset];
  offset++;
  qid->vers = *(uint32_t *)(msg + offset);
  offset += 4;
  qid->path = *(uint64_t *)(msg + offset);

  printf("size: %u nbytes: %u\n", size, nbytes);

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
  offset = 0;
  packheader(msg, &hdr, &offset);
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
    return 0;
  }

  return *(uint32_t *)msg;
}

int rver(SOCKET fd, Version *ver)
{
  uint32_t size, nbytes;
  unsigned char msg[128];
  int offset;

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
  offset = 0;
  unpackheader(msg, &ver->hdr, &offset);
  unpack32(msg, &ver->msize, &offset);
  if(unpackstr(msg, ver->vlen, ver->version, 8, &offset)< 0) {
    perror("rver unpackstr");
    return -1;
  }

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
  char errstr[256];
  Qid qids[MAXWELEM * QIDSZ];
  int nwqid;
  char *wname[MAXWELEM];
  uint16_t nwname;
  Stat stat;

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
  err.ename = errstr;

  if((r = sattach(fd, &att)) < 0) goto Exit;
  if((r = rattach(fd, &qid, &err)) < 0) goto Exit;

  if(err.elen != 0) {
    fprintf(stderr, "Rerror: %s\n", err.ename);
    r = -1;
    goto Exit;
  }
  printf("QID[ %u, %u, %llu ]\n", qid.type, qid.vers, qid.path);

  nwname = 2;
  wname[0] = "sys";
  wname[1] = "src";
  if((r = swalk(fd, att.fid, 1, nwname, wname)) < 0) goto Exit;
  if((nwqid = rwalk(fd, qids, &err)) < 0) goto Exit;
  if(err.elen != 0) {
    fprintf(stderr, "Rerror: %s\n", err.ename);
    r = -1;
    goto Exit;
  }

  puts("got qids:");
  for(int i = 0; i < nwqid; i++) {
    printf("QID[ %u, %u, %llu ]\n", qids[i].type, qids[i].vers, qids[i].path);
  }

  if((r = sstat(fd, 1)) < 0) goto Exit;
  if((r = rstat(fd, &stat, &err)) < 0) goto Exit;

  if((r = sclunk(fd, 0)) < 0) goto Exit;
  if((r = rclunk(fd, &err)) < 0) goto Exit;
  else printf("Received Rclunk\n");


  Exit:
	closesocket(fd);
#ifdef _WIN32
	WSACleanup();
#endif
	exit(r);
}
