#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>      
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <tins/tins.h>

using namespace Tins;

#define DEBUG  0

static int callback(struct nfq_q_handle * qh,
                    struct nfgenmsg * nfmsg,
                    struct nfq_data * nfa,
                    void * data)
{
   u_int32_t id;
   struct nfqnl_msg_packet_hdr *ph;
   ph = nfq_get_msg_packet_hdr(nfa);   
   id = ntohl(ph->packet_id);

   // modify packet
   unsigned char * packet;

   int size = nfq_get_payload(nfa, &packet);

   IP ip(packet, size);

   UDP * udp = ip.find_pdu<UDP>();

   if (udp) {
      printf("Got UDP packet "
	"(sport=%hu dport=%hu length=%hu checksum=%hu)\n",
         udp->sport(),
         udp->dport(),
         udp->length(),
         udp->checksum());

      RawPDU * raw = udp->find_pdu<RawPDU>();

      if (raw) {
         RawPDU::payload_type & payload = raw->payload();

         printf("payload=[");

         for (size_t i=0; i < payload.size(); ++i) {
            putchar(payload[i]);
         }

         printf("]\n");

         std::string data("Mangled!!!");

         RawPDU::payload_type new_payload(data.begin(), data.end());

         raw->payload(new_payload);
      }
      else {
         printf("Unable to get to RawPDU\n");
      }

      PDU::serialization_type buffer = ip.serialize();

      IP modified_ip(&buffer[0], buffer.size());

      udp = modified_ip.find_pdu<UDP>();

      if (udp) {
         printf("Modified UDP packet "
            "(sport=%hu dport=%hu length=%hu checksum=%hu)\n",
            udp->sport(),
            udp->dport(),
            udp->length(),
            udp->checksum());

         raw = udp->find_pdu<RawPDU>();

         if (raw) {
            RawPDU::payload_type & payload = raw->payload();

            printf("payload=[");

            for (size_t i=0; i < payload.size(); ++i) {
               putchar(payload[i]);
            }

            printf("]\n");
         }

         return nfq_set_verdict(qh, id, NF_ACCEPT, buffer.size(), &buffer[0]);
      }
   }

   return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}


int main(int argc, char ** argv)
{
   struct nfq_handle * h;
   struct nfq_q_handle * qh;
   int fd;
   int rv;
   char buf[4096] __attribute__ ((aligned));

   unsigned short queue_num = 0;

   if (argc >= 2) {
      queue_num = atoi(argv[1]);
   }

   printf("Creating nfqueue handle\n");

   h = nfq_open();

   if (! h) {
      fprintf(stderr, "Error during nfq_open()\n");
      exit(1);
   }

   if (nfq_unbind_pf(h, AF_INET) < 0) {
      fprintf(stderr, "Error during nfq_unbind_pf()\n");
      exit(1);
   }

   if (nfq_bind_pf(h, AF_INET) < 0) {
      fprintf(stderr, "Error during nfq_bind_pf()\n");
      exit(1);
   }

   printf("Binding handle to queue '%hu'\n", queue_num);

   qh = nfq_create_queue(h, queue_num, &callback, NULL);

   if (!qh) {
      fprintf(stderr, "Error during nfq_create_queue()\n");
      exit(1);
   }

   if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
      fprintf(stderr, "Error setting NFQNL_COPY_PACKET\n");
      exit(1);
   }

   fd = nfq_fd(h);

   unsigned int packet_count=0;

   while ((rv = recv(fd, buf, sizeof(buf), 0))) {
      if (DEBUG) printf("packet received\n");
      nfq_handle_packet(h, buf, rv);

      packet_count++;

      if (packet_count % 1000 == 0) {
         printf("Processed %u packets ...\n", packet_count);
      }
   }

   nfq_destroy_queue(qh);
   nfq_close(h);

   exit(0);
}
