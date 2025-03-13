#include <net/ethernet.h>
#include <netinet/ip.h>
#include <pcap.h>

typedef struct _ETHER_HEADER {
  uint8_t Dst[6];
  uint8_t Src[6];
  uint16_t Type;
} __attribute__((packed)) H_ETHER;

typedef struct _H_IP {
  unsigned char IHL : 4; // Bit field
  unsigned char VER : 4; // Bit field
  unsigned char ToS;
  unsigned short Length;
  unsigned short ID;
  unsigned short Frag;
  unsigned char TTL;
  unsigned char Protocol;
  unsigned short Checksum;
  unsigned char SrcAddr[4];
  unsigned char DstAddr[4];
} __attribute__((packed)) H_IP;

typedef struct _H_TCP {
  unsigned short SrcPort;
  unsigned short DstPort;
  unsigned int nSeq;
  unsigned int nAck;
  unsigned char DataOffset;
  unsigned char FIN : 1;
  unsigned char SYN : 1;
  unsigned char RST : 1;
  unsigned char PSH : 1;
  unsigned char ACK : 1;
  unsigned char URG : 1;
  unsigned char ECE : 1;
  unsigned char CWR : 1;
  unsigned short WindowSize;
  unsigned short Checksum;
  unsigned short UrgPointer;
} __attribute__((packed)) H_TCP;

typedef struct _USER_PACKET {
  u_long nSeq;
  u_long nAck;
  u_short nPayload;
} __attribute__((packed)) USER_PACKET;

class CUserPcap {
public:
  char m_szIP[16]{};

public:
  int DisplayInfo(int, struct pcap_pkthdr *, const u_char *);
  char *IpAddress(const u_char[]);
};