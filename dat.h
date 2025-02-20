/* 9P constants */
enum {
	/* msg types */
	Tversion = 100,
	Rversion,
	Tauth = 102,
	Rauth,
	Tattach = 104,
	Rattach,
	Terror = 106,	/* illegal */
	Rerror,
	Tflush = 108,
	Rflush,
	Twalk = 110,
	Rwalk,
	Topen = 112,
	Ropen,
	Tcreate = 114,
	Rcreate,
	Tread = 116,
	Rread,
	Twrite = 118,
	Rwrite,
	Tclunk = 120,
	Rclunk,
	Tremove = 122,
	Rremove,
	Tstat = 124,
	Rstat,
	Twstat = 126,
	Rwstat,

	OREAD = 0,
	OWRITE = 1,
	ORDWR = 2,
	OEXEC = 3,
	OTRUNC = 0x10,
	ORCLOSE = 0x40,		/* remove on close */

	DMDIR = 0x80000000, /* broken on windows */
	DMAPPEND = 0x40000000,
	DMEXCL = 0x20000000,	/* exclusive use */
	DMAUTH = 0x08000000,	/* auth file */
	DMTMP = 0x04000000,

	NOTAG = 0xFFFF,
	NOFID = 0xFFFFFFFF, /* broken on windows */

	/* limits */
	IOHDRSZ = 24,		/* max size of 9P io header */
	MAXFDATA = 8192,	/* max data payload */
	MAXWELEM = 16,		/* max elements in walk */
	MAXMSG = (IOHDRSZ + MAXFDATA), /* max message size */
};

typedef struct Qid Qid;
struct Qid {
  uint8_t type;
  uint32_t vers;
  uint64_t path;
};

/* shared by all 9P messages */
typedef struct Header Header;
struct Header {
  uint32_t size;
  uint8_t type;
  uint16_t tag;
};

/* version specific fields */
typedef struct Version Version ;
struct Version {
  Header hdr;
  uint32_t msize;
  uint16_t vlen;
  char version[8]; /* usually "9P2000" */
};

typedef struct Attach Attach;
struct Attach {
  Header hdr;
  uint32_t fid;
  uint32_t afid;
  uint16_t ulen;
  char *uname;
  uint16_t alen;
  char *aname;
};
