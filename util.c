#include <stdint.h>
#include <string.h>
#include "dat.h"
#include "fns.h"

void
pack8(unsigned char *buf, unsigned char val, int *offset)
{
  buf[(*offset)++] = val;
}

void
pack16(unsigned char *buf, uint16_t val, int *offset)
{
  *(uint16_t *)(buf + *offset) = val;
  *offset += 2;
}

void
pack32(unsigned char *buf, uint32_t val, int *offset)
{
  *(uint32_t *)(buf + *offset) = val;
  *offset += 4;
}

void
pack64(unsigned char *buf, uint64_t val, int *offset)
{
  *(uint64_t *)(buf + *offset) = val;
  *offset += 8;
}

void
packstr(unsigned char *buf, char *str, int *offset)
{
  int len;

  len = strlen(str);
  pack16(buf, len, offset);
  memcpy(buf + *offset, str, len);
  *offset += len;
}

void packqid(unsigned char *buf, Qid *qid, int *offset) {
  pack8(buf, qid->type, offset);
  pack32(buf, qid->vers, offset);
  pack64(buf, qid->path, offset);
}

void
packheader(unsigned char *buf, Header *hdr, int *offset)
{
  pack32(buf, hdr->size, offset);
  pack8(buf, hdr->type, offset);
  pack16(buf, hdr->tag, offset);
}

void unpack8(unsigned char *buf, unsigned char *val, int *offset) {
  *val = buf[(*offset)++];
}

void unpack16(unsigned char *buf, uint16_t *val, int *offset) {
  *val = *(uint16_t *)(buf + *offset);
  *offset += 2;
}

void unpack32(unsigned char *buf, uint32_t *val, int *offset) {
  *val = *(uint32_t *)(buf + *offset);
  *offset += 4;
}

void unpack64(unsigned char *buf, uint64_t *val, int *offset) {
  *val = *(uint64_t *)(buf + *offset);
  *offset += 8;
}

int unpackstr(unsigned char *buf, uint16_t *len, char *dst, uint32_t size, int *offset) {
  unpack16(buf, len, offset);
  if (*len > size) {
    return -1;
  }
  memcpy(dst, buf + *offset, *len);
  dst[*len] = '\0';
  *offset += *len;
  return 0;
}

void unpackheader(unsigned char *msg, Header *hdr, int *offset) {
  unpack32(msg, &hdr->size, offset);
  unpack8(msg, &hdr->type, offset);
  unpack16(msg, &hdr->tag, offset);
}

void unpackqid(unsigned char *buf, Qid *qid, int *offset) {
  unpack8(buf, &qid->type, offset);
  unpack32(buf, &qid->vers, offset);
  unpack64(buf, &qid->path, offset);
}

/* unpackerr is similar to str, but truncates the string if its too large */
void unpackerr(unsigned char *buf, Error *err, int *offset) {
  unpack16(buf, &err->elen, offset);
  if (err->elen > sizeof err->ename) {
    err->elen = sizeof err->ename;
  }
  memcpy(err->ename, buf + *offset, err->elen);
  err->ename[err->elen] = '\0';
  *offset += err->elen;
}

void unpackstat(unsigned char *buf, Stat *stat, int *offset) {
  unpack16(buf, &stat->size, offset);
  unpack16(buf, &stat->type, offset);
  unpack32(buf, &stat->dev, offset);
  unpackqid(buf, &stat->qid, offset);
  unpack32(buf, &stat->mode, offset);
  unpack32(buf, &stat->atime, offset);
  unpack32(buf, &stat->mtime, offset);
  unpack64(buf, &stat->length, offset);
  unpackstr(buf, &stat->namelen, stat->name, sizeof stat->name, offset);
  unpackstr(buf, &stat->uidlen, stat->uid, sizeof stat->uid, offset);
  unpackstr(buf, &stat->gidlen, stat->gid, sizeof stat->gid, offset);
  unpackstr(buf, &stat->muidlen, stat->muid, sizeof stat->muid, offset);
}
