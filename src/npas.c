/*************************************************************************
	> File Name: npas.c
	> Author: Dapiqing
	> Mail:971774262@qq.com 
	> Created Time: Thu May  3 09:01:24 2018
 ************************************************************************/
#include "npas_common.h"

#define BUFSIZE 1514
#define FILE_NAME "xxx"
bool write2file(char *filename, char *str)
{
	if(filename == NULL && str == NULL)
	{
		return false;
	}
	int fd = open(filename, O_RDWR | O_APPEND);
	if(fd == -1)
	{
		printf("open fail\n");
		return false;
	}
	char buf[64] = { 0 };
	time_t time_now;
	time_now = time(&time_now);
	strftime(buf, sizeof(buf), "%y-%m-%d %H:%M\t", localtime(&time_now));
	write(fd, buf, strlen(buf));
	write(fd, str, strlen(str));
	close(fd);

	return true;
}

bool decode_tcp(const unsigned char *packet_buff, unsigned int len)
{
	if(!packet_buff && len < sizeof(struct tcp_hdr))
	{
		return false;
	}
	struct tcp_hdr *tcp_hdr = (struct tcp_hdr *) packet_buff;
	if(ntohs(tcp_hdr->th_dport) == 80 || ntohs(tcp_hdr->th_sport) == 80)
	{
		char *host = strstr((char *) packet_buff + sizeof(struct tcp_hdr), "Host: ");
		if(host)
		{
			char *CF = strstr(host, "\r\n");
			char ret[1024] = { 0 };
			memcpy(ret, host + 6, (CF - host - 6) > 254 ? 254 : CF - host - 6);
			char *payload = (char *) packet_buff + sizeof(struct tcp_hdr);
			if(strncmp(payload, "GET ", 4) == 0 || strncmp(payload, "POST", 4) == 0)
			{
				char *end = strstr(payload, "HTTP");
				if(end != NULL)
				{
					strncat(ret, payload + 4, end - payload - 4);
				}
			}
			strcat(ret, "\n");
			write2file(FILE_NAME, ret);
		}

	}
	return true;
}

bool decode_ip(const unsigned char *packet_buff, unsigned int len)
{
	if(!packet_buff && len < 20)
	{
		return false;
	}
	struct ip_hdr *ip_hdr = (struct ip_hdr *) packet_buff;
	if(ip_hdr->protocol == 0x06)
	{
		decode_tcp(packet_buff + sizeof(struct ip_hdr), len - sizeof(struct ip_hdr));
	} else
	{

	}
	return true;
}

void ethernet_protocol_callback(unsigned char *argument, const struct pcap_pkthdr *packet_header, const unsigned char *packet_content)
{
	struct linux_cooked *linux_cooked;
	unsigned short protocol_type;
	linux_cooked = (struct linux_cooked *) packet_content;

	protocol_type = ntohs(linux_cooked->protocol_type);
	switch (protocol_type)
	{
	case 0x0800:
		{
			decode_ip(packet_content + sizeof(struct linux_cooked), packet_header->caplen - sizeof(struct linux_cooked));
			break;
		}
	case 0x0806:
		printf("The network layer is ARP protocol\n");
		break;
	case 0x0835:
		printf("The network layer is RARP protocol\n");
		break;
	default:
		break;
	}
	//usleep(800*1000);  
}

int main(int argc, char *argv[])
{
	daemon(1, 1);
	char error_content[100];  
	pcap_t *pcap_handle;
#if 0
	net_interface = pcap_lookupdev(error_content);
	printf("%s\n", net_interface);
	if(NULL == net_interface)
	{
		perror("pcap_lookupdev");
		exit(-1);
	}
#endif
	pcap_handle = pcap_open_live("venet0:0", BUFSIZE, 1, 0, error_content);

	int linktype = pcap_datalink(pcap_handle);
	if(pcap_loop(pcap_handle, -1, ethernet_protocol_callback, (unsigned char *) &linktype) < 0)
	{
		perror("pcap_loop");
	}

	pcap_close(pcap_handle);
	return 0;
}
