void pack8(unsigned char *buf, unsigned char val, int *offset);
void pack16(unsigned char *buf, uint16_t val, int *offset);
void pack32(unsigned char *buf, uint32_t val, int *offset);
void pack64(unsigned char *buf, uint64_t val, int *offset);
void packstr(unsigned char *buf, char *str, int *offset);
int packheader(Header *hdr, unsigned char *msg);
