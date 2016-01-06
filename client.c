#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include "msg.h"
#include "sock_util.h"

// State
#define STATE_INIT 0
#define STATE_WAIT_OFFER 1
#define STATE_WAIT_REPLY 2
#define STATE_NEED_EXT 3

void usage();
void init_as_discover(msg_t *);
void init_as_request(msg_t*, msg_t*);
void init_as_ext_request(msg_t*);
void init_as_release(msg_t*);
void set_state(int st);

uint32_t assigned_ip = -1;
uint32_t assigned_netmask = -1;
int sd;
struct sockaddr_in skt;
int st;

//Signal handler
void trap(int);
void timeout(int);
sigset_t block;
int quit_flag = 0;

int 
main(int argc, char** argv)
{
  if(argc != 2) {
    usage();
    exit(EXIT_FAILURE);
  }
  //DHCP Server IP from argv.
  char *server_ip = argv[1];
  
  /*
   * setup socket.
   */
  int count, datalen;
  char sbuf[96];
  in_port_t srv_port;
  struct in_addr ipaddr;
  fd_set fds, rdfds;
  
  //Initialize my socket.
  if ((sd = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
    perror("socket");
    exit(EXIT_FAILURE);
  }
  FD_ZERO(&rdfds);
  FD_SET(sd, &rdfds);

  //Setup server port and IP
  srv_port = 51230;
  inet_aton(server_ip, &ipaddr);
  skt.sin_family = AF_INET;
  skt.sin_port = htons(srv_port);
  skt.sin_addr.s_addr = htonl(ipaddr.s_addr);

  /*
   * setup signal handler
   */
  //SIGINT handler.
  struct sigaction sa;
  memset(&sa, 0, sizeof(struct sigaction));
  sa.sa_handler = trap;
  sa.sa_flags |= SA_RESTART;

  if (sigaction(SIGINT, &sa, NULL) != 0) {
    fprintf(stderr, "Failed to attach sigaction\n");
    exit(EXIT_FAILURE);
  }
  
  //SIGALRM handler.
  struct sigaction sa2;
  sigemptyset(&block);
  sigaddset(&block, SIGALRM);
  memset(&sa2, 0, sizeof(struct sigaction));
  sa2.sa_handler = timeout;
  sa2.sa_flags |= SA_RESTART;

  if (sigaction(SIGALRM, &sa2, NULL) != 0) {
    fprintf(stderr, "Failed to attach sigaction\n");
    exit(EXIT_FAILURE);
  }

  set_state(STATE_INIT);
  while(!quit_flag) {
    if(st == STATE_INIT) {
      //Send Discover.
      msg_t discover_msg;
      init_as_discover(&discover_msg);
      socklen_t sktlen = sizeof skt;
      send_to(sd, &discover_msg, sizeof discover_msg, 0,
              (struct sockaddr *)&skt, sktlen);
      set_state(STATE_WAIT_OFFER);
    } else if(st == STATE_WAIT_OFFER) {
      //Recieve offer msg.
      msg_t offer_msg;
      socklen_t sktlen = sizeof skt;
      struct timeval tv;
      tv.tv_sec = 10;
      tv.tv_usec = 0;
      int n;
      memcpy(&fds, &rdfds, sizeof(fd_set));
      if((n = select(sd+1, &fds, NULL, NULL, &tv)) < 0) {
        perror("select");
        exit(EXIT_FAILURE);
      }
      if(n == 0) {
        //Timeout..
        fprintf(stderr, "Timeout..\n");
        set_state(STATE_INIT);
      } else {
        if(FD_ISSET(sd, &rdfds)) {
          recv_from(sd, &offer_msg, sizeof offer_msg, 0,
                    (struct sockaddr *)&skt, &sktlen);
          if(offer_msg.code == CODE_SUCCESS) {
            //Send request msg.
            msg_t request_msg;
            init_as_request(&request_msg, &offer_msg);
            send_to(sd, &request_msg, sizeof request_msg, 0,
                    (struct sockaddr *)&skt, sktlen);
            set_state(STATE_WAIT_REPLY);
          } else if(offer_msg.code == CODE_FAILED_OFFER) {
            //No IP Available..
            assigned_ip = -1;
            assigned_netmask = -1;
            quit_flag = 1;
          } else {
            fprintf(stderr, "Illigal code\n");
          }
        }
      }
    } else if(st == STATE_WAIT_REPLY) {
      //Recieve reply msg.
      msg_t reply_msg;
      socklen_t sktlen = sizeof skt;
      struct timeval tv;
      tv.tv_sec = 10;
      tv.tv_usec = 0;
      int n;
      memcpy(&fds, &rdfds, sizeof(fd_set));
      if((n = select(sd+1, &fds, NULL, NULL, &tv)) < 0) {
        perror("select");
        exit(EXIT_FAILURE);
      }
      if(n == 0) {
        fprintf(stderr, "Timeout..\n");
        set_state(STATE_INIT);
      } else {
        recv_from(sd, &reply_msg, sizeof reply_msg, 0,
                  (struct sockaddr *)&skt, &sktlen);
        if(reply_msg.code == CODE_SUCCESS) {
          assigned_ip = reply_msg.ip;
          assigned_netmask = reply_msg.netmask;
          struct in_addr ip_addr;
          ip_addr.s_addr = assigned_ip;
          int time_to_live;
          time_to_live = reply_msg.time_to_live;
          set_state(STATE_NEED_EXT);
          alarm(time_to_live / 2);
          fprintf(stderr, "IP Assigned: %s\n", inet_ntoa(ip_addr));
          fprintf(stderr, "Time to live: %d\n", time_to_live);
        } else if(reply_msg.code == CODE_ERROR_REP) {
          //Requested IP was already assigned to other client.
          assigned_ip = -1;
          assigned_netmask = -1;
          quit_flag = 1;
        }
      }
    } 
  }
}

void usage() {
  fprintf(stderr, "./mydhcpc server-IP-address\n");
}

void init_as_discover(msg_t *msg)
{
  msg->type = MSG_DISCOVER;
  msg->code = 0;
  msg->time_to_live = 0;
  msg->ip = 0;
  msg->netmask = 0;
}

void init_as_request(msg_t *req_msg, msg_t* off_msg)
{
  req_msg->type = MSG_REQUEST;
  req_msg->code = CODE_ASSING_REQ;
  req_msg->time_to_live = off_msg->time_to_live;
  req_msg->ip = off_msg->ip;
  req_msg->netmask = off_msg->netmask;
}

void init_as_ext_request(msg_t* msg)
{
  msg->type = MSG_REQUEST;
  msg->code = CODE_EXT_REQ;
  msg->time_to_live = 40;
  msg->ip = assigned_ip;
  msg->netmask = assigned_netmask;
}

void init_as_release(msg_t *msg)
{
  msg->type = MSG_RELEASE;
  msg->code = CODE_SUCCESS;
  msg->time_to_live = 0;
  msg->ip = assigned_ip;
  msg->netmask = 0;
}

void set_state(int s)
{
  printf("update state: %d -> %d\n", st, s);
  st = s;
}

//Signal handler
void trap(int no)
{
  if(assigned_ip != -1 && assigned_netmask != -1) {
    msg_t release_msg;
    int count;
    socklen_t sktlen = sizeof skt;
    init_as_release(&release_msg);
    send_to(sd, &release_msg, sizeof release_msg, 0,
            (struct sockaddr *)&skt, sktlen);
  }
  exit(EXIT_SUCCESS);
}

void timeout(int no)
{
  sigprocmask(SIG_BLOCK, &block, NULL);
  if(st == STATE_NEED_EXT) {
    //Send ext request.
    msg_t request_msg;
    socklen_t sktlen = sizeof skt;
    init_as_ext_request(&request_msg);
    send_to(sd, &request_msg, sizeof request_msg, 0,
           (struct sockaddr *)&skt, sktlen);
    set_state(STATE_WAIT_REPLY);
  } else {
    assigned_ip = -1;
    assigned_netmask = -1;
    set_state(STATE_INIT);
  }
  sigprocmask(SIG_UNBLOCK, &block, NULL);
}
