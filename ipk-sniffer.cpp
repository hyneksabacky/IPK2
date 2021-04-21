//https://www.tcpdump.org/pcap.html
//http://yuba.stanford.edu/~casado/pcap/section3.html
//https://www.geeksforgeeks.org/c-program-display-hostname-ip-address/

#include <iostream>
#include <getopt.h>
#include <cstring>
#include <pcap.h>
#include <netinet/in.h>
#include <string>
#include <sys/time.h>
#include <math.h>
#include <arpa/inet.h>
#include <iomanip>
#include <map>
#include <string_view>

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

class Restrictions {
    public:
        char* device = NULL;
        int numof_packets = -1;
        std::string filter_exp = "port ";
        std::map<std::string, bool> possible_packets {
            {"ALL", true},
            {"TCP", false},
            {"UDP", false},
            {"ICMP", false},
            {"ARP", false},
            {"OTHER", false}
        };

        void set_possible_packets(std::string packet){
            possible_packets["ALL"] = false;
            possible_packets[packet] = true;
        }

        void set_all_possible_packets(){
            possible_packets["TCP"] = true;
            possible_packets["UDP"] = true;
            possible_packets["ICMP"] = true;
            possible_packets["ARP"] = true;
            possible_packets["OTHER"] = true;
        }
} restr;

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

//  Uniform way of printing all packets.
//  Using one main loop for 16 bytes, then two loops inside.
//  One for hexadecimal representation, one for ASCII representation.
void print_packet(const u_char* packet, int packet_len){
    using namespace std;
    cout<< endl;
    for(int i = 0; i< ((packet_len+16-1)/16); i++){                                     //rounding up division
        cout << "0x" << setw(4) << setfill('0') << hex << i*16 << ":  ";
        for( int j = 0; j<16; j++){
            if(j == 8){
                cout << " ";
            }
            if(i*16+j >= packet_len){
                cout << "   ";
            } else {
                cout << setw(2) << setfill('0') <<hex << (int)packet[i*16+j] << " ";
            }
        } 

        cout << " ";

        for( int j = 0; j<16; j++){
            if(j == 8){
                cout << " ";
            }
            if(i*16+j >= packet_len){
                cout << " ";
            } else {
                if(isprint(packet[i*16+j])){
                    cout << packet[i*16+j];
                } else{
                    cout << ".";
                }
            }
        }
        cout << endl;
    }
    cout << endl;
}

void ipv4_packet(const struct pcap_pkthdr* pkthdr,const u_char* packet){
#define SIZE_ETHERNET 14
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const char *payload; /* Packet payload */

	u_int size_ip;
	u_int size_tcp;

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

    print_time(pkthdr->ts);
    
    printf("%s : %d ", inet_ntoa(ip->ip_src), tcp->th_sport);
    printf("> %s : %d, ", inet_ntoa(ip->ip_dst), tcp->th_dport);
    printf("length %d bytes\n", pkthdr->caplen);

    print_packet(packet, pkthdr->caplen);
    
}

void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    /* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

	const struct sniff_ethernet *ethernet; /* The ethernet header */

	ethernet = (struct sniff_ethernet*)(packet);

    //std::cout<<ethernet->ether_type<<std::endl;
    if(htons(ethernet->ether_type) == 0x0800){
        if(restr.possible_packets["ICMP"])
            ipv4_packet(pkthdr, packet);
    } else if(htons(ethernet->ether_type) == 0x0806){
        if(restr.possible_packets["ARP"]){
            std::cout << std::endl <<"----------------------------------" <<std::endl;
            std::cout << "0x" << std::setw(4) << std::setfill('0') << std::hex <<htons(ethernet->ether_type) <<  std::endl ;
            std::cout <<"----------------------------------" << std::endl << std::endl;
        }
    }

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
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		    /* The compiled filter expression */
    bpf_u_int32 mask;		        /* The netmask of our sniffing device */
    bpf_u_int32 net;		        /* The IP of our sniffing device */
    struct pcap_pkthdr header;	    /* The header that pcap gives us */
    const u_char *packet;		    /* The actual packet */
    
    int opt,a,b,c, d, e, index;
    opterr = 0;
    while ((opt = getopt_long(argc,argv,"i:p:tun:h", longopts, &index)) != EOF)
    {
        switch(opt)
        {
            case 'h': CLI_arg_usage();
            case 'i':   if(optarg!=NULL){
                            restr.device = optarg;
                        }
                        break;                
            case 'f':   if(optarg!=NULL){
                            restr.device = optarg;
                        }
                        break;
            case 'p': restr.filter_exp = restr.filter_exp.append(optarg); break;
            case 't': restr.set_possible_packets("TCP"); break;
            case 'u': restr.set_possible_packets("UDP"); break;
            case 'n': restr.numof_packets = atoi(optarg); break;
            case 'x': restr.set_possible_packets("ICMP"); break;
            case 'y': restr.set_possible_packets("ARP"); break;
            case '?':   if(optopt == 'i'){
                            continue;
                        }
            default: CLI_arg_usage(); exit(1);
        }
    }
    if(restr.possible_packets["ALL"])
        restr.set_all_possible_packets();
    restr.device = interface_option(restr.device);
    if (restr.device == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    printf("Device: %s\n", restr.device);
	
    if (pcap_lookupnet(restr.device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", restr.device);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(restr.device, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", restr.device, errbuf);
        return(2);
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", restr.device);
		return(2);
	}


    if (pcap_compile(handle, &fp, restr.filter_exp.c_str(), 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", restr.filter_exp.c_str(), pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", restr.filter_exp.c_str(), pcap_geterr(handle));
        return(2);
    }

    pcap_loop(handle, (int)restr.numof_packets, my_callback, NULL);

    return 0;
}