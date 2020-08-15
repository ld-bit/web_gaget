#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<linux/tcp.h>
#include<linux/ip.h>
#include<linux/udp.h>
#include<linux/if_arp.h>
#include<linux/icmp.h>
#include<linux/if_ether.h>
#include<linux/ip.h>
void print_udp(char* buf);
void print_icmp(char* buf);
void print_tcp(char* buf);
void print_mac(char* buf);
void print_ip(char* buf);
void print_arp(char* buf);
int main()
{
  int sfd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
  char buf[2000]={};
  while(1)
  {
    //清空buf
    memset(buf,0x00,sizeof(buf));
    //从链路层读取链路层数据
    int r=read(sfd,buf,sizeof(buf));
    if(r<=0)
      break;
    //打印帧头消息
    print_mac(buf);
  }
}
void print_mac(char* buf)
{
  //获取帧头
  struct ethhdr* p=(struct ethhdr*)buf;
  //打印帧头的信息,链路层(帧头部包括) : 源MAC地址 , 目标MAC地址 
  printf("-------------链路层(帧)头----------\n");
  printf("源MAC地址: %2x:%2x:%2x:%2x:%2x:%2x\n",p->h_source[0],p->h_source[1],p->h_source[2],p->h_source[3],p->h_source[4],p->h_source[5]);
  printf("目标MAC地址: %2x:%2x:%2x:%2x:%2x:%2x\n",p->h_dest[0],p->h_dest[1],p->h_dest[2],p->h_dest[3],p->h_dest[4],p->h_dest[5]);
  printf("-----------------------------------\n");
  //打印下一层的协议的头部信息
  if(ntohs(p->h_proto)==ETH_P_IP)
  {
    print_ip(buf+sizeof(struct ethhdr));
  }
  else if(ntohs(ntohs(p->h_proto)==ETH_P_ARP))
  {
  print_arp(buf+sizeof(struct ethhdr));
  }
}
union un{
   unsigned t1 : 3;
   unsigned t2 : 13;
};
void print_ip(char* buf)
{
  struct iphdr * p=(struct iphdr*)buf;
  printf("--------------IP协议头-------------\n");
  printf("4位版本号: %u\n",p->version);
  printf("4位首部长度: %u\n",p->ihl);
  printf("8位服务类型: %u\n",p->tos);
  printf("16位总长度: %u\n",p->tot_len);
  printf("16位标识: %u\n",p->id);
  union un*u=(union un*)&p->frag_off; 
  printf("3位标志: %u\n",u->t1);
  printf("13 位偏移量: %u\n",u->t2);
  printf("8位生存时间: %u\n",p->ttl);
  printf("8位协议: %u\n",p->protocol);
  printf("16位首部校验和: %u\n",p->check);
  struct in_addr ad;
  ad.s_addr=p->saddr;
  printf("32位源IP地址: %s\n",inet_ntoa(ad));
  ad.s_addr=p->daddr;
  printf("32位目标IP地址: %s\n",inet_ntoa(ad));
  printf("-----------------------------------\n");
  if(p->protocol==IPPROTO_TCP)
  {
   print_tcp(buf+sizeof(struct iphdr));
  }
  else if(p->protocol==IPPROTO_UDP)
  {
   print_udp(buf+sizeof(struct udphdr));
  }
  else if(p->protocol==IPPROTO_ICMP)
  {
   print_icmp(buf+sizeof(struct icmphdr));
  }
}
void print_tcp(char* buf)
{
  struct tcphdr* p=(struct tcphdr*)buf;
  printf("-----------------------------------\n");
  printf("----------------TCP首部------------\n");
  printf("16位源端口号: %hu\n",ntohs(p->source));
  printf("16位目标端口口号: %hu\n",ntohs(p->dest));
  printf("32位序号: %u\n",p->seq);
  printf("32位确认序号: %u\n",p->ack_seq);
  printf("4位首部长度: %u\n",p->res1);
  printf("URG(紧急指针): %u\n",p->urg);
  printf("ACK(确认序号有效): %u\n",p->ack);
  printf("PSH(接收方应该尽快的将这个报文接受到应用层): %u\n",p->psh);
  printf("RST(重新连接): %u\n",p->rst);
  printf("SYN(发起连接): %u\n",p->syn);
  printf("FIN(发端完成发送任务): %u\n",p->fin);
  printf("16位窗口大小: %u\n",p->window);
  printf("16位检验和: %u\n",p->check);
  printf("16位紧急指针: %u\n",p->urg_ptr);
  printf("-----------------------------------\n");
}
void print_udp(char* buf)
{
  struct udphdr* p=(struct udphdr*)buf;
  printf("---------------UDP首部-------------\n");
  printf("16位源端口号: %u\n",ntohs(p->source));
  printf("16位目标端口号: %u\n",ntohs(p->dest));
  printf("16位UDP长度: %u\n",p->len);
  printf("16位UDP检验和: %u\n",p->check);
  printf("-----------------------------------\n");
}
void print_icmp(char* buf)
{
  struct icmphdr* p=(struct icmphdr*)buf;
  printf("--------------ICMP首部-------------\n");
  printf("8位类型: %u\n",p->type);
  printf("8位代码: %u\n",p->code);
  printf("16位检验和: %hu\n",(p->checksum));
  printf("-----------------------------------\n");
}
void print_arp(char* buf)
{
  struct arphdr* p=(struct arphdr*)buf; 
  printf("------------ARP协议头--------------\n");
  printf("源MAC: %2x:%2x:%2x:%2x:%2x:%2x\n",p->ar_sha[0],p->ar_sha[1],p->ar_sha[2],p->ar_sha[3],p->ar_sha[4],p->ar_sha[5]);
  printf("目标MAC: %2x:%2x:%2x:%2x:%2x:%2x\n",p->ar_tha[0],p->ar_tha[1],p->ar_tha[2],p->ar_tha[3],p->ar_tha[4],p->ar_tha[5]);
  printf("源ip: %hhu.%hhu.%hhu.%hhu\n",p->ar_sip[0],p->ar_sip[1],p->ar_sip[2],p->ar_sip[3]);
  printf("源ip: %hhu.%hhu.%hhu.%hhu\n",p->ar_tip[0],p->ar_tip[1],p->ar_tip[2],p->ar_tip[3]);
  printf("-----------------------------------\n");
}
