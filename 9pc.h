#ifndef _9PC_H_
#define _9PC_H_

#include <stdint.h>

#include "dat.h"
#include "fns.h"

/* Socket Setup */
SOCKET socketsetup(char *host, char *port);

/* Protocol Version */
int sver(SOCKET fd);
int rver(SOCKET fd, Version *ver);

/* Authentication */
int sauth(SOCKET fd, uint32_t afid, char *uname, char *aname);
int rauth(SOCKET fd, Qid *qid, Error *err);

/* Attach to filesystem */
int sattach(SOCKET fd, Attach *a);
int rattach(SOCKET fd, Qid *qid, Error *err);

/* File/Directory Operations */
int swalk(SOCKET fd, uint32_t fid, uint32_t newfid, uint16_t nwname, char **wname);
int rwalk(SOCKET fd, Qid *qids, Error *err);

int sopen(SOCKET fd, uint32_t fid, uint8_t mode);
int ropen(SOCKET fd, Qid *qid, uint32_t *iounit, Error *err);

int screate(SOCKET fd, uint32_t fid, char *name, uint32_t perm, uint8_t mode);
int rcreate(SOCKET fd, Qid *qid, uint32_t *iounit, Error *err);

int sread(SOCKET fd, uint32_t fid, uint64_t offset, uint32_t count);
int rread(SOCKET fd, unsigned char *data, uint32_t *count, Error *err);

int swrite(SOCKET fd, uint32_t fid, uint64_t offset, uint32_t count, unsigned char *data);
int rwrite(SOCKET fd, uint32_t *count, Error *err);

int sclunk(SOCKET fd, uint32_t fid);
int rclunk(SOCKET fd, Error *err);

int sremove(SOCKET fd, uint32_t fid);
int rremove(SOCKET fd, Error *err);

/* File Information */
int sstat(SOCKET fd, uint32_t fid);
int rstat(SOCKET fd, Stat *stat, Error *err);

int swstat(SOCKET fd, uint32_t fid, Stat *stat);
int rwstat(SOCKET fd, Error *err);

/* Control Messages */
int sflush(SOCKET fd, uint16_t oldtag);
int rflush(SOCKET fd);

/* Directory Helpers */
int readdir(unsigned char *data, uint32_t count, Stat *stats);
void printstat(Stat stat);

#endif /* _9PC_H_ */