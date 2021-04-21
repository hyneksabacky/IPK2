//https://www.tcpdump.org/pcap.html
//http://yuba.stanford.edu/~casado/pcap/section3.html
//https://www.geeksforgeeks.org/c-program-display-hostname-ip-address/

#include <iostream>
#include <getopt.h>
#include <cstring>
#include <pcap.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/time.h>
#include <math.h>
#include <arpa/inet.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

	/* Ethernet header */
	struct sniff_ethernet {
		    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		    u_short ether_type; /* IP? ARP? RARP? etc */
	};

	/* IP header */
	struct sniff_ip {
		    u_char ip_vhl;		/* version << 4 | header length >> 2 */
		    u_char ip_tos;		/* type of service */
		    u_short ip_len;		/* total length */
		    u_short ip_id;		/* identification */
		    u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* don't fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		    u_char ip_ttl;		/* time to live */
		    u_char ip_p;		/* protocol */
		    u_short ip_sum;		/* checksum */
		    struct in_addr ip_src,ip_dst; /* source and dest address */
	};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
	typedef u_int tcp_seq;

	struct sniff_tcp {
	        u_short th_sport;	/* source port */
		    u_short th_dport;	/* destination port */
		    tcp_seq th_seq;		/* sequence number */
		    tcp_seq th_ack;		/* acknowledgement number */
		    u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		    u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		    u_short th_win;		/* window */
		    u_short th_sum;		/* checksum */
		    u_short th_urp;		/* urgent pointer */
    };

void print_time(struct timeval timestamp){
    char buff[26];
    char zone[5];
    int millisec;
    struct tm* tm_info;


    millisec = lrint(timestamp.tv_usec/1000.0);

    tm_info = localtime(&timestamp.tv_sec);

    strftime(buff, 26, "%Y-%m-%dT%H:%M:%S", tm_info);
    printf("%s.%03d", buff, millisec);
    strftime(buff, 26, "%z", tm_info);
    printf("+%c%c:00 ", buff[1], buff[2]);
}

void ip_packet(){
    
}

void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    /* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const char *payload; /* Packet payload */

	u_int size_ip;
	u_int size_tcp;

	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    print_time(pkthdr->ts);
    
    printf("%s : %d ", inet_ntoa(ip->ip_src), tcp->th_sport);
    printf("> %s : %d, ", inet_ntoa(ip->ip_dst), tcp->th_dport);
    printf("length %d bytes\n", pkthdr->caplen);

    //printf("%hu", ethernet->ether_type);
    int i = 0;
    int size_of_payload = pkthdr->caplen-(SIZE_ETHERNET + size_ip + size_tcp);
    //std::cout << size_of_payload << std::endl;
    
    std::cout << pkthdr->len << std::endl;
    for (int i = 0; i<size_of_payload; i++){
        if(i%4 == 0){
            std::cout << " ";
        }
        if(isprint(payload[i])){
            std::cout << payload[i];
        } else {
            std::cout << ".";
        }
    }

    // std::cout << std::endl << "-------------------" << size_of_payload << std::endl;
    // std::cout << std::endl << "-------------------" << SIZE_ETHERNET + size_ip + size_tcp<< std::endl;
    std::cout << std::endl;

}

char *interface_option(char *dev){
    pcap_if_t *devices = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    if(pcap_findalldevs(&devices, errbuf) != 0){
        fprintf(stderr, "Couldn't find any devices: %s\n", errbuf);
        exit(2);
    }

    while (devices!=NULL){
        if(dev == NULL){
            std::cout << devices->name << std::endl;
        } else if (!strcmp(dev, devices->name)){
            return devices->name;
        }
        devices = devices->next;
    }
    if(dev != NULL){
        fprintf(stderr, "Invalid interface.\n");
        exit(1);
    }
    exit(0);
    
}

const struct option longopts[] =
{
    {"icmp",        no_argument,          0,   'x'},
    {"arp",         no_argument,          0,   'y'},
    {"tcp",         no_argument,          0,   't'},
    {"udp",         no_argument,          0,   'u'},
    {"interface",   required_argument,    0,   'f'},
    {"help",        no_argument,          0,   'h'},
    {0,0,0,0},
};

void CLI_arg_usage(){
    fprintf(stderr,
    "\nusuage is: \n\n" 
    "./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n"
    "\n"
    "interface | i : <value>  - for selecting interface.\n" 
    "          | p : <value>  - number of port (if not specified, all ports). \n" 
    "      tcp | t : <switch> - tcp packets only. \n"
    "      udp | u : <switch> - udp packets only. \n"
    "      arp |   : <switch> - only ARP frames.\n"
    "     icmp |   : <switch> - only ICMPv4 and ICMPv6 packets. \n"
    "          | n : <value>  - number of packets to be shown (default is 1).\n"
    "     help | h : <help>   - show this message. \n\n"
    );
    exit(1);
}

using namespace std;
int main(int argc, char **argv)
{
    pcap_t *handle;		            /* Session handle */
    char *dev; //= "rl0";		    /* Device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		    /* The compiled filter expression */
    char filter_exp[] = "port 22";	/* The filter expression */
    bpf_u_int32 mask;		        /* The netmask of our sniffing device */
    bpf_u_int32 net;		        /* The IP of our sniffing device */
    struct pcap_pkthdr header;	    /* The header that pcap gives us */
    const u_char *packet;		    /* The actual packet */

    /* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	char *payload; /* Packet payload */

	u_int size_ip;
	u_int size_tcp;
    int numof_packets = -1;
    
    char* device = NULL;
    int opt,a,b,c, d, e, index;
    opterr = 0;
    while ((opt = getopt_long(argc,argv,"i:p:tun:h", longopts, &index)) != EOF)
    {
        switch(opt)
        {
            case 'h': CLI_arg_usage();
            case 'i':   if(optarg!=NULL){
                            device = optarg;
                        }
                        break;                
            case 'f':   if(optarg!=NULL){
                            device = optarg;
                        }
                        break;
            case 'p': b = 1; cout << "value of p is "<< optarg <<endl ; break;
            case 't': c = 1; cout <<" t is enabled"<<c <<endl; break;
            case 'u': d = 1; cout <<" u is enabled"<<d <<endl; break;
            case 'n': numof_packets = atoi(optarg); break;
            case 'x': e = 1; cout << "icmp is enabled"<<endl ; break;
            case 'y': e = 1; cout << "arp is enabled"<<endl ; break;
            case '?':   if(optopt == 'i'){
                            continue;
                        }
            default: CLI_arg_usage(); exit(1);
        }
    }

    dev = interface_option(device);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    printf("Device: %s\n", dev);
	
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
		return(2);
	}

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    pcap_loop(handle, (int)numof_packets, my_callback, NULL);

    return 0;
}