#include <stdio.h>
#include <assert.h>

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

#include "9pc.h"



void printstat(Stat stat)
{
  printf("  size: %u\n", stat.size);
  printf("  type: %u\n", stat.type);
  printf("  dev: %u\n", stat.dev);
  printf("  qid: { type: %u, vers: %u, path: %llu }\n", stat.qid.type,
         stat.qid.vers, stat.qid.path);
  printf("  mode: %#o\n", stat.mode);
  printf("  atime: %u\n", stat.atime);
  printf("  mtime: %u\n", stat.mtime);
  printf("  length: %llu\n", stat.length);
  printf("  name: (%u) %.*s\n", stat.namelen, stat.namelen, stat.name);
  printf("  uid: (%u) %.*s\n", stat.uidlen, stat.uidlen, stat.uid);
  printf("  gid: (%u) %.*s\n", stat.gidlen, stat.gidlen, stat.gid);
  printf("  muid: (%u) %.*s\n", stat.muidlen, stat.muidlen, stat.muid);
}

int
readdir(unsigned char *data, uint32_t count, Stat *stats)
{
  int offset, nstat;
  Stat zerost = {0};

  nstat = 0;
  offset = 0;

  while(offset < count) {
    unpackstat(data, stats + nstat, &offset);
    if(memcmp(&zerost, stats + nstat, sizeof(Stat)) == 0)
      break;
    nstat++;
  }

  return nstat;
}

int
sread(SOCKET fd, uint32_t fid, uint64_t foffset, uint32_t count)
{
  const uint32_t total_size = 7 + 4 + 8 + 4;
  unsigned char msg[7 + 4 + 8 + 4];
  int offset;
  Header hdr = { total_size, Tread, 0 };
  int nbytes;

  offset = 0;
  packheader(msg, &hdr, &offset);
  pack32(msg, fid, &offset);
  pack64(msg, foffset, &offset);
  pack32(msg, count, &offset);

  nbytes = send(fd, (char *)msg, total_size, 0);
  return nbytes;
}

int
rread(SOCKET fd, unsigned char *data, uint32_t *count, Error *err)
{
  uint32_t size, nbytes;
  unsigned char msg[MAXMSG];
  int offset;
  Header hdr;

  size = rsize(fd);
  printf("size: %u\n", size);
  if(size == 0) {
    perror("rread size");
    return -1;
  }
  else if(size > sizeof msg) {
    fprintf(stderr, "rread: message too large: %u\n", size);
    return -1;
  }

  nbytes = recv(fd, (char *)msg + 4, size - 4, 0);

  offset = 0;
  unpackheader(msg, &hdr, &offset);

  if(hdr.type == Rerror) {
    unpackstr(msg, &err->elen, err->ename, 256, &offset);
    return 0;
  }

  if(hdr.type != Rread) {
    fprintf(stderr, "unexpected message type: %u\n", msg[4]);
    return -1;
  }

  unpack32(msg, count, &offset);
  memcpy(data, msg + offset, *count);
  return nbytes;
}

unsigned char *
rreadall(SOCKET fd, uint32_t *count, Error *err)
{
  uint32_t size, nbytes;
  unsigned char *msg, *dst;
  int offset;
  Header hdr;

  size = rsize(fd);
  if(size == 0) {
    perror("rreadall size");
    return NULL;
  }

  msg = malloc(size);
  if(msg == NULL) {
    perror("rreadall malloc");
    return NULL;
  }

  nbytes = recv(fd, (char *)msg + 4, size - 4, 0);
  if(nbytes != size - 4) {
    perror("rreadall: incomplete message received");
    return NULL;
  }

  offset = 0;
  unpackheader(msg, &hdr, &offset);

  if(hdr.type == Rerror) {
    unpackstr(msg, &err->elen, err->ename, 256, &offset);
    return NULL;
  }

  if(hdr.type != Rread) {
    fprintf(stderr, "unexpected message type: %u", msg[4]);
    return NULL;
  }

  unpack32(msg, count, &offset);

  dst = malloc(*count + 1);
  if(dst == NULL) {
    perror("rreadall malloc");
    return NULL;
  }
  memcpy(dst, msg + offset, *count);
  dst[*count] = '\0';

  free(msg);
  return dst;
}

int
sopen(SOCKET fd, uint32_t fid, uint8_t mode)
{
  const uint32_t total_size = 7 + 4 + 1;
  unsigned char msg[7 + 4 + 1];
  int offset;
  Header hdr = { total_size, Topen, 0 };
  int nbytes;

  offset = 0;
  packheader(msg, &hdr, &offset);
  pack32(msg, fid, &offset);
  pack8(msg, mode, &offset);

  nbytes = send(fd, (char *)msg, total_size, 0);
  return nbytes;
}

int
ropen(SOCKET fd, Qid *qid, uint32_t *iounit, Error *err)
{
  uint32_t size, nbytes;
  unsigned char msg[8192];
  int offset;
  Header hdr;

  size = rsize(fd);
  if(size == 0) {
    perror("ropen size");
    return -1;
  }
  else if(size > sizeof msg) {
    fprintf(stderr, "message too large: %u", size);
    return -1;
  }

  nbytes = recv(fd, (char *)msg + 4, size - 4, 0);
  if(nbytes != size - 4) {
    perror("ropen: incomplete message received");
    return -1;
  }

  offset = 0;
  unpackheader(msg, &hdr, &offset);

  if(hdr.type == Rerror) {
    unpackstr(msg, &err->elen, err->ename, 256, &offset);
    return 0;
  }

  if(hdr.type != Ropen) {
    fprintf(stderr, "unexpected message type: %u", msg[4]);
    return -1;
  }

  unpackqid(msg, qid, &offset);
  unpack32(msg, iounit, &offset);

  return 0;
}

int
swstat(SOCKET fd, uint32_t fid, Stat *stat)
{
  uint32_t total_size = 7 + 2 + 2 + 2 + 4 + 13 + 4 + 4 + 4 + 8 \
                        + 2 + stat->namelen + 2 + stat->uidlen \
                        + 2 + stat->gidlen + 2 + stat->muidlen;
  unsigned char msg[1024];
  int offset;
  Header hdr = { total_size, Twstat, 0 };
  int nbytes;

  assert(total_size <= sizeof msg);

  offset = 0;
  packheader(msg, &hdr, &offset);
  pack32(msg, fid, &offset);
  pack16(msg, stat->size, &offset);
  pack16(msg, stat->type, &offset);
  pack32(msg, stat->dev, &offset);
  packqid(msg, &stat->qid, &offset);
  pack32(msg, stat->mode, &offset);
  pack32(msg, stat->atime, &offset);
  pack32(msg, stat->mtime, &offset);
  pack64(msg, stat->length, &offset);
  packstr(msg, stat->name, &offset);
  packstr(msg, stat->uid, &offset);
  packstr(msg, stat->gid, &offset);
  packstr(msg, stat->muid, &offset);

  nbytes = send(fd, (char *)msg, total_size, 0);
  return nbytes;
}

int
rwstat(SOCKET fd, Error *err)
{
  uint32_t size, nbytes;
  unsigned char msg[8192];
  int offset;
  Header hdr;

  size = rsize(fd);
  if(size == 0) {
    perror("rwstat size");
    return -1;
  }
  else if(size > sizeof msg) {
    fprintf(stderr, "message too large: %u", size);
    return -1;
  }

  nbytes = recv(fd, (char *)msg + 4, size - 4, 0);
  if(nbytes != size - 4) {
    perror("rwstat: incomplete message received");
    return -1;
  }

  offset = 0;
  unpackheader(msg, &hdr, &offset);

  if(hdr.type == Rerror) {
    unpackstr(msg, &err->elen, err->ename, 256, &offset);
    return 0;
  }

  if(hdr.type != Rwstat) {
    fprintf(stderr, "unexpected message type: %u", msg[4]);
    return -1;
  }

  return 0;
}

int
sstat(SOCKET fd, uint32_t fid)
{
  const uint32_t total_size = 7 + 4;
  unsigned char msg[7 + 4];
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
  uint16_t statsz; /* unused */
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
    fprintf(stderr, "rstat: message too large: %u", size);
    return -1;
  }

  nbytes = recv(fd, (char *)msg + 4, size - 4, 0);
  if(nbytes != size - 4) {
    fprintf(stderr, "rstat: incomplete message received. expected %u got %u\n", size, nbytes);
    return -1;
  }

  offset = 0;
  unpackheader(msg, &hdr, &offset);

  if(hdr.type == Rerror) {
    unpackstr(msg, &err->elen, err->ename, 256, &offset);
    return 0;
  }

  if(hdr.type != Rstat) {
    fprintf(stderr, "rstat: unexpected message type: %u", hdr.type);
    return -1;
  }

  unpack16(msg, &statsz, &offset);
  unpack16(msg, &stat->size, &offset);
  unpack16(msg, &stat->type, &offset);
  unpack32(msg, &stat->dev, &offset);
  unpackqid(msg, &stat->qid, &offset);
  unpack32(msg, &stat->mode, &offset);
  unpack32(msg, &stat->atime, &offset);
  unpack32(msg, &stat->mtime, &offset);
  unpack64(msg, &stat->length, &offset);
  unpackstr(msg, &stat->namelen, stat->name, sizeof stat->name, &offset);
  unpackstr(msg, &stat->uidlen, stat->uid, sizeof stat->uid, &offset);
  unpackstr(msg, &stat->gidlen, stat->gid, sizeof stat->gid, &offset);
  unpackstr(msg, &stat->muidlen, stat->muid, sizeof stat->muid, &offset);

  return 0;
}

int
sflush(SOCKET fd, uint16_t oldtag)
{
  const uint32_t total_size = 7 + 2; /* header + tag */
  unsigned char msg[7 + 2];
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
    perror("rflush: incomplete message received");
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
    perror("rwalk: incomplete message received");
    return -1;
  }

  offset = 0;
  unpackheader(msg, &hdr, &offset);

  /* check message type */
  if(hdr.type == Rerror) {
    unpackstr(msg, &err->elen, err->ename, 256, &offset);
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
  const uint32_t total_size = 7 + 4;
  unsigned char msg[7 + 4];
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
    perror("rclunk: incomplete message received");
    return -1;
  }

  offset = 0;
  unpackheader(msg, &hdr, &offset);

  if(hdr.type == Rerror) {
    unpackstr(msg, &err->elen, err->ename, 256, &offset);
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
    perror("rattach: incomplete message received");
    return -1;
  }

  offset = 0;
  unpackheader(msg, &hdr, &offset);

  /* check message type */
  if(hdr.type == Rerror) {
    unpackstr(msg, &err->elen, err->ename, 256, &offset);
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
  const uint32_t total_size = 4 + 1 + 2 + 4 + 2 + 6;
  unsigned char msg[4 + 1 + 2 + 4 + 2 + 6];
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
    perror("rver: incomplete message received");
    return -1;
  }

  /* unpack */
  offset = 0;
  unpackheader(msg, &ver->hdr, &offset);
  unpack32(msg, &ver->msize, &offset);
  if(unpackstr(msg, &ver->vlen, ver->version, 8, &offset)< 0) {
    perror("rver unpackstr");
    return -1;
  }

  return 0;
}

SOCKET socketsetup(char *host, char *port);

#if 0
int
main(int argc, char *argv[])
{
  SOCKET fd;
  char *host, port[6];
  int r, nwqid, nstat;
  uint16_t nwname;
  uint32_t iounit;
  uint32_t count;
  char errstr[256];
  char *wname[MAXWELEM];
  unsigned char data[8192];
  unsigned char *buf;
  Version ver;
  Attach att;
  Qid qid;
  Qid qids[MAXWELEM * QIDSZ];
  Error err;
  Stat stat;
  Stat *stats;
  int nbytes;

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

  fd = socketsetup(host, port);
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
  wname[0] = "lib";
  wname[1] = "rob";
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
  if(err.elen != 0) {
    fprintf(stderr, "Rerror: %s\n", err.ename);
    r = -1;
    goto Exit;
  }
  /* print all fields of stat with a prefix saying what each field is */
  printf("Stat structure:\n");

  /* cant test swstat yet without auth */

  /* open and read dir contents */
  iounit = 0;
  if((r = sopen(fd, 1, OREAD)) < 0) goto Exit;
  if((r = ropen(fd, &qid, &iounit, &err)) < 0) goto Exit;

  if(err.elen != 0) {
    fprintf(stderr, "Rerror: %s\n", err.ename);
    r = -1;
    goto Exit;
  }

  if(iounit == 0) iounit = 8192;

  puts("sending read");
  if((r = sread(fd, 1, 1, 128)) < 0) goto Exit;
  puts("reading");
  if((r = rread(fd, data, &count, &err)) < 0) goto Exit;
  if(err.elen != 0) {
    fprintf(stderr, "Rerror: %s\n", err.ename);
    r = -1;
    goto Exit;
  }

  data[count] = '\0';
  printf("READ[ count: %u str: %s ]\n", count, data);

  stats = malloc(1024);
  nstat = readdir(data, count, stats);
   printf("READ[ count: %u str: %s ]\n", count, data);
  for(int i = 0; i < nstat; i++) {
    printf("Stat %d:\n", i);
    printstat(stats[i]);
  }
  free(stats);


  if((r = sread(fd, 1, 0, stat.length)) < 0) goto Exit;
  buf = rreadall(fd, &count, &err);
  if(err.elen != 0) {
    fprintf(stderr, "Rerror: %s\n", err.ename);
    r = -1;
    goto Exit;
  }
  printf("READ[ count: %u str: %s ]\n", count, buf);
  free(buf);

Exit:
  r = sflush(fd, 0);
  r = rflush(fd);
  r = sclunk(fd, 0);
  r = rclunk(fd, &err);
  printf("Received Rclunk\n");
	closesocket(fd);
#ifdef _WIN32
	WSACleanup();
#endif
	exit(r);
}
#endif

SOCKET socketsetup(char *host, char *port)
{
  struct addrinfo hints;
  struct addrinfo *res;
  SOCKET fd;
  int r;

#ifdef _WIN32
	WSADATA wsa;
	if(WSAStartup(MAKEWORD(2,2), &wsa) != 0){
		fprintf(stderr, "wsastartup failed\n");
		exit(1);
	}
#endif

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

  return fd;
}
