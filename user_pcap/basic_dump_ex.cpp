#include <arpa/inet.h>
#include <climits>
#include <netinet/ip.h>
#include <pcap.h>
#include <stdio.h>

#include "user_pcap.h"

int main() {
  pcap_if_t *alldevs;
  pcap_if_t *d;
  int inum;
  int i = 0;
  pcap_t *adhandle;
  int res;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct tm *ltime;
  char timestr[16];
  struct pcap_pkthdr *header;
  const u_char *pkt_data;
  time_t local_tv_sec;

  /* Retrieve the device list */
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
    return -1;
  }

  /* Print the list */
  for (d = alldevs; d; d = d->next) {
    printf("%d. %s", ++i, d->name);
    if (d->description)
      printf(" (%s)\n", d->description);
    else
      printf(" (No description available)\n");
  }

  if (i == 0) {
    printf("\nNo interfaces found! Make sure Npcap is installed.\n");
    return -1;
  }

  printf("Enter the interface number (1-%d):", i);
  scanf("%d", &inum);

  if (inum < 1 || inum > i) {
    printf("\nInterface number out of range.\n");
    /* Free the device list */
    pcap_freealldevs(alldevs);
    return -1;
  }

  /* Jump to the selected adapter */
  for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++)
    ;

  /* Open the adapter */
  if ((adhandle =
           pcap_open_live(d->name, // name of the device
                          65536,   // portion of the packet to capture.
                                   // 65536 grants that the whole packet will be
                                   // captured on all the MACs.
                          1,     // promiscuous mode (nonzero means promiscuous)
                          1000,  // read timeout
                          errbuf // error buffer
                          )) == NULL) {
    fprintf(stderr,
            "\nUnable to open the adapter. %s is not supported by Npcap\n",
            d->name);
    /* Free the device list */
    pcap_freealldevs(alldevs);
    return -1;
  }

  printf("\nlistening on %s...\n", d->description);

  /* At this point, we don't need any more the device list. Free it */
  pcap_freealldevs(alldevs);

  int nOut = 0;
  /* Retrieve the packets */
  CUserPcap userPcap;
  while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {

    if (res == 0)
      /* Timeout elapsed */
      continue;

    nOut = userPcap.DisplayInfo(res, header, pkt_data);
    if (nOut >= 259)
      break;
  }

  if (res == -1) {
    printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
    return -1;
  }

  pcap_close(adhandle);
  return 0;
}