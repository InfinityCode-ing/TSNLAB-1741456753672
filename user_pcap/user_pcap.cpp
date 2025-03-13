// clang++ -g basic_dump_ex.cpp user_pcap.cpp -lpcap -o basic_dump_ex
// ./basic_dump_ex

#include "user_pcap.h"
#include <cstdio>

int CUserPcap::DisplayInfo(int res, struct pcap_pkthdr *header,
                           const u_char *pkt_data) {

  //  printf("CUserPcap::DisplayInfo\n");
  //  printf("res = %d, header->len = %u\n", res, header->len);

  H_ETHER *pEther = (H_ETHER *)pkt_data;
  // ntohs(uint16_t) 으로 변경된 값과 비교 해야 한다.
  // https://en.wikipedia.org/wiki/EtherType
  // 변경하지 않을 경우 0x0008 : IPv4
  if (pEther->Type == 0x0008) {
    H_IP *pIP = (H_IP *)(pkt_data + sizeof(H_ETHER));

    u_int nSrcAddr = *((u_int *)(pIP->SrcAddr));
    u_int nDstAddr = *((u_int *)(pIP->DstAddr));

    // 174517050 : https://www.kisa.or.kr/ : 58.235.102.10
    // 2216011968 : guest ip : 192.168.21.132
    // if ((nSrcAddr == 2216011968 || nDstAddr == 2216011968) &&
    //    (nSrcAddr == 174517050 || nDstAddr == 174517050) &&
    //    pIP->Protocol == 6) {
    if ((nSrcAddr == 174517050 || nDstAddr == 174517050) &&
        pIP->Protocol == 6) {

      H_TCP *pTCP = (H_TCP *)(pkt_data + sizeof(H_ETHER) + pIP->IHL * 4);

      // payload
      const u_char *ip_header;
      const u_char *tcp_header;
      const u_char *payload;

      int ethernet_header_length = 14;
      int ip_header_length;
      int tcp_header_length;
      int payload_length;

      ip_header = pkt_data + ethernet_header_length;
      ip_header_length = ((*ip_header) & 0x0F);
      ip_header_length = ip_header_length * 4;

      tcp_header = pkt_data + ethernet_header_length + ip_header_length;
      tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
      tcp_header_length = tcp_header_length * 4;
      int total_headers_size =
          ethernet_header_length + ip_header_length + tcp_header_length;
      payload_length = header->caplen - (ethernet_header_length +
                                         ip_header_length + tcp_header_length);
      payload = pkt_data + total_headers_size;

      if (payload_length > 0) {
        printf("Src Address : %s\n", IpAddress(pIP->SrcAddr));
        printf("Dst Address : %s\n", IpAddress(pIP->DstAddr));

        printf("SrcPort     : %d\n", ntohs(pTCP->SrcPort));
        printf("DstPort     : %d\n", ntohs(pTCP->DstPort));
        printf("nSeq        : %u\n", ntohl(pTCP->nSeq));
        printf("nAck        : %u\n", ntohl(pTCP->nAck));
        printf("DataOffset  : 0x%02x\n", pTCP->DataOffset);
        printf("FIN         : %d\n", pTCP->FIN);
        printf("SYN         : %d\n", pTCP->SYN);
        printf("RST         : %d\n", pTCP->RST);
        printf("PSH         : %d\n", pTCP->PSH);
        printf("ACK         : %d\n", pTCP->ACK);
        printf("URG         : %d\n", pTCP->URG);
        printf("ECE         : %d\n", pTCP->ECE);
        printf("CWR         : %d\n", pTCP->CWR);
        printf("WindowSize  : %d\n", ntohs(pTCP->WindowSize));
        printf("Checksum    : 0x%04x\n", ntohs(pTCP->Checksum));
        printf("UrgPointer  : %d\n", pTCP->UrgPointer);
        printf("Payload     : %d\n", payload_length);
        puts("");

        for (int i = 0; i < payload_length; ++i) {
          printf("%02x ", *(payload + i));
        }
        puts("");
        puts("///////////////////////////////////////////////////////////////");
        puts("");
      }

      if (payload_length == 0 && pTCP->FIN == 1) {
        return 259;
      }
    }
  } else {
    return 0;
  }

  return 1;
}

char *CUserPcap::IpAddress(const u_char ip[]) {
  //  memset(m_szIP, 0, sizeof(m_szIP));
  sprintf(m_szIP, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  return m_szIP;
}