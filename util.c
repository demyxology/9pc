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

int
packheader(Header *hdr, unsigned char *msg)
{
  int offset = 0;

  pack32(msg, hdr->size, &offset);
  pack8(msg, hdr->type, &offset);
  pack16(msg, hdr->tag, &offset);

  return offset;
}
