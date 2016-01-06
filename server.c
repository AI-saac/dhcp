#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include "sock_util.h"
#include "msg.h"

/*
 * Abstract  bidirectional list
 */
typedef struct node {
  struct node *fp;
  struct node *bp;
  void* data;
} node_t;

/*
 * Client data
 */
typedef struct {
  int lease;
  struct in_addr cli_adr;
  unsigned short cli_port;
  short status;
} client_t;


#define ST_WAIT_DISCOVER 0
#define ST_WAIT_REQUEST 1
#define ST_WAIT_REQ_OR_RELEASE 2

/*
 * Timeout list.
 */
typedef struct {
  client_t *cli;
  long start;
  long exp;
} timeout_t;

#define TIMEOUT 10

/*
 * IP list data
 */
typedef struct {
  uint32_t ip;
  uint32_t netmask;
} iplist_t;

/*
 * Request waiting list.
 */
typedef struct {
  client_t* cli;
  iplist_t*ip;
} req_wait_t;

/*
 * IP <-> Client Assign list.
 */
typedef struct {
  client_t* cli;
  iplist_t* ip;
} assign_t;


void usage();

/*
 * List Headers
 */
node_t *client_root;
node_t *iplist_root;
node_t *req_wait_root;
node_t *assign_root;
node_t *timeout_root;

/*
 * Node Operation
 */
node_t* new_node(void* data);
void free_node(node_t*);
void insert_node(node_t* root, node_t *n);
void remove_node(node_t*);
int  empty(node_t*);
node_t* peek_head(node_t*);

/*
 * ip manegement.
 */
int load_ip_file(char* fname);
uint32_t netmask_to_uint32_t(char*);
void uint32_t_to_netmask(uint32_t, char*);
void uint32_t_to_ipstr(uint32_t, char*);
node_t* search_iplist(uint32_t *ip, uint32_t *netmask);
node_t* search_assign(client_t*);

/*
 * Client management.
 */
node_t* search_client(struct in_addr*, unsigned short*);
node_t* search_req_wait(client_t*);

/*
 * Timeout management
 */
long get_time();
node_t* search_timeout(client_t*);
void reflesh_timeout(client_t*, long, int);
sigset_t block;
void timeout();

/*
 * Message initializers.
 */
void init_as_failed_offer(msg_t *msg);
void init_as_offer(iplist_t*, msg_t *msg);
void init_as_reply(msg_t*, iplist_t *);
void init_as_failed_reply(msg_t*);

/*
 * Utility function
 */
void init_roots();
node_t* ensure_client(struct in_addr* addr, unsigned short *port);

/*
 * State Functions
 */
int sd;
struct sockaddr_in skt;
socklen_t sktlen = sizeof skt;
void st_discover(int sd, msg_t *msg, client_t *cli);
void st_request(int sd, msg_t *msg, client_t *cli);
void st_release(int sd, msg_t *msg, client_t *cli);
void st_illigal(int sd, msg_t *msg, client_t *cli);

void (*st_funs[3][5])(int sd, msg_t *msg, client_t *cli) =
{
  {st_discover, st_illigal, st_illigal, st_illigal, st_illigal},
  {st_illigal, st_illigal, st_request, st_illigal, st_illigal},
  {st_illigal, st_illigal, st_request, st_illigal, st_release}
};


int main(int argc, char** argv) {
  
  if(argc != 2) {
    usage();
    exit(EXIT_FAILURE);
  }

  init_roots();

  char* config_file = argv[1];
  if (load_ip_file(config_file) < 0) {
    fprintf(stderr, "Failed to load config-file\n");
    exit(EXIT_FAILURE);
  }

  /*
   * Signal handler
   */
  struct sigaction sa;
  sigemptyset(&block);
  sigaddset(&block, SIGALRM);
  memset(&sa, 0, sizeof(struct sigaction));
  sa.sa_handler = timeout;
  sa.sa_flags |= SA_RESTART;
  if (sigaction(SIGALRM, &sa, NULL) != 0) {
    fprintf(stderr, "Failed to attach sigaction\n");
    exit(EXIT_FAILURE);
  }

  in_port_t myport;
  struct sockaddr_in myskt;
  if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  
  myport = 51230;
  bzero(&myskt, sizeof myskt);
  myskt.sin_family = AF_INET;
  myskt.sin_port = htons(myport);
  myskt.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(sd, (struct sockaddr *)&myskt, sizeof myskt) < 0) {
    perror("bind");
    exit(EXIT_FAILURE);
  }

  //Output IP Addr
  char  *ptr2 = inet_ntoa(myskt.sin_addr);
  printf("ip: %s\n", ptr2);

  //Main loop
  for(;;) {
    msg_t msg;
    recv_from(sd, &msg, sizeof msg, 0, (struct sockaddr *)&skt, &sktlen);
    node_t *msgNode = ensure_client(&skt.sin_addr, &skt.sin_port);
    client_t *cli = msgNode->data;
    (st_funs[cli->status][msg.type - 1])(sd, &msg, cli);
  }
}

void usage() {
  fprintf(stderr, "./mydhcpd config-file\n");
}

/*
 * Node operation.
 */
node_t* new_node(void* data)
{
  node_t* n = malloc(sizeof(node_t));
  n->data = data;
  return n;
}

void free_node(node_t *n)
{
  free(n->data);
  free(n);
}

void insert_node(node_t *root, node_t *n)
{
  n->fp = root;
  n->bp = root->bp;
  root->bp->fp = n;
  root->bp = n;
}

void remove_node(node_t *n)
{
  n->bp->fp = n->fp;
  n->fp->bp = n->bp;
}

int empty(node_t* root)
{
  return root->fp == root && root->bp == root;
}

node_t* peek_head(node_t* root)
{
  if(empty(root)) {
    return NULL;
  }
  return root->fp;
}

/*
 * Load ip file.
 */
int load_ip_file(char *fname)
{
  FILE *fp;

  if ((fp = fopen(fname, "r")) == NULL) {
    fprintf(stderr, "Failed to open ip list file: %s\n", fname);
    return -1;
  }
  char ip[256];
  char mask[256];
  int ret;

  while((ret = fscanf(fp, "%s%s", &ip[0], &mask[0])) != EOF) {
    node_t *n;
    iplist_t *i;
    
    if ((i = malloc(sizeof(iplist_t))) == NULL) {
      fprintf(stderr, "Failed to allocate memory of iplist_t\n");
      return -1;
    }

    struct in_addr addr;
    inet_aton(ip, &addr);
    uint32_t nm = netmask_to_uint32_t(mask);

    i->ip = addr.s_addr;
    i->netmask = nm;

    if ((n = new_node(i)) == NULL) {
      fprintf(stderr, "Failed to allocate memory of node_t\n");
      return -1;
    }
    insert_node(iplist_root, n);
  }
  fclose(fp);
  return 0;
}

uint32_t netmask_to_uint32_t(char* netmask)
{
  uint32_t a, b, c, d, res;
  sscanf(netmask, "%" SCNu32 ".%" SCNu32 ".%" SCNu32 ".%" SCNu32, &a, &b, &c, &d);
  res = (a << 24) + (b << 16) + (c << 8) + d;
  return res;
}

void uint32_t_to_netmask(uint32_t mask, char *str)
{
  uint8_t a, b, c, d;
  a = (mask & 0xFFFFFFFF) >> 24;
  b = (mask & 0xFFFFFF) >> 16;
  c = (mask & 0xFFFF) >> 8;
  d = (mask & 0xFF);
  sprintf(str, "%" SCNu8 ".%" SCNu8 ".%" SCNu8 ".%" SCNu8, a, b, c, d);
}

void uint32_t_to_ipstr(uint32_t ip, char *str)
{
  uint8_t a, b, c, d;
  a = (ip & 0xFFFFFFFF) >> 24;
  b = (ip & 0xFFFFFF) >> 16;
  c = (ip & 0xFFFF) >> 8;
  d = (ip & 0xFF);
  //Endian..
  sprintf(str, "%" SCNu8 ".%" SCNu8 ".%" SCNu8 ".%" SCNu8, d, c, b, a);
}

node_t* search_iplist(uint32_t *ip, uint32_t *mask)
{
  node_t *c;
  for(c = iplist_root->fp; c != iplist_root; c = c->fp) {
    iplist_t *i = c->data;
    if(i->ip == *ip && i->netmask == *mask) {
      return c;
    }
  }
  return NULL;
}

node_t* search_assign(client_t *cli)
{
  node_t *c;
  for(c = assign_root->fp; c != assign_root; c = c->fp) {
    assign_t *a = c->data;
    if(a->cli == cli)
      return c;
  }
  return NULL;
}


node_t* search_client(struct in_addr* addr, unsigned short *port)
{
  node_t *c;
  for(c = client_root->fp; c != client_root; c = c->fp) {
    client_t *cli = c->data;
    if(cli->cli_adr.s_addr == addr->s_addr && cli->cli_port == *port) {
      return c;
    }
  }
  return NULL;
}

node_t* search_req_wait(client_t* w)
{
  node_t *c;
  for(c = req_wait_root->fp; c != req_wait_root; c = c->fp) {
    client_t *cli = ((req_wait_t *)c->data)->cli;
    if(cli == w) {
      return c;
    }
  }
  return NULL;
}

long get_time()
{
  struct timeval tp;
  gettimeofday(&tp, NULL);
  return tp.tv_sec;
}

node_t* search_timeout(client_t *w)
{
  node_t *c;
  for(c = timeout_root->fp; c != timeout_root; c = c->fp) {
    client_t *cli = ((timeout_t *)c->data)->cli;
    if(cli == w) {
      return c;
    }
  }
  return NULL;
}

void reflesh_timeout(client_t *cli, long length, int needAppend)
{
  node_t *tnode;
  if ((tnode = search_timeout(cli)) != NULL) {
    if(tnode->fp == timeout_root) {
      //list End
      remove_node(tnode);
    } else if(tnode->bp == timeout_root) {
      remove_node(tnode);
      long crrtime = get_time();
      long next_alarm = ((timeout_t*)tnode->fp->data)->exp - crrtime;
      alarm(((timeout_t*)tnode->fp->data)->exp - crrtime);
    } else {
      //Middle
      remove_node(tnode);
    }
  }
  if(needAppend) {
    long crrtime = get_time();
    timeout_t *t = tnode->data;
    t->cli = cli;
    t->start = crrtime;
    t->exp = crrtime + length;
    if (empty(timeout_root)) {
      alarm(length);
    }
    insert_node(timeout_root, tnode);
  } else {
    free(tnode);
  }
}

void timeout()
{
  fprintf(stderr, "Time out handler invoked\n");
  sigprocmask(SIG_BLOCK, &block, NULL);
  if(empty(timeout_root)) {
    fprintf(stderr, "Illigal timeout\n");
  } else {
    node_t *h = timeout_root->fp;
    client_t* cli = ((timeout_t*)h->data)->cli;
    switch(cli->status) {
    case ST_WAIT_REQUEST:
      {
        node_t *w;
        if ((w = search_req_wait(cli)) != NULL) {
          remove_node(w);
          free(w);
        }
      }
      break;
    case ST_WAIT_REQ_OR_RELEASE:
      {
        node_t *a;
        if ((a = search_assign(cli)) != NULL) {
          remove_node(a);
          //Release IP.
          node_t *n;
          if ((n = new_node(((assign_t*)a->data)->ip)) == NULL) {
            fprintf(stderr, "Failed to allocate memory of node_t\n");
            exit(EXIT_FAILURE);
          }
          insert_node(iplist_root, n);
          struct in_addr ip_addr;
          assign_t *as = a->data;
          ip_addr.s_addr = as->ip->ip;
          fprintf(stderr, "IP Released: %s\n", inet_ntoa(ip_addr));
          free(a);
        } else {
          fprintf(stderr, "Illigal assign state\n");
        }
      }
      break;
    }
    if(h->fp == timeout_root) {
      fprintf(stderr, "Time out head alarm become reset\n");
      alarm(0);
    } else {
      long crrtime = get_time();
      fprintf(stderr, "Normal timeout\n");
      long next_alarm = ((timeout_t*)h->fp->data)->exp - crrtime;
      fprintf(stderr, "Next alarm is: %ld\n", next_alarm);
      alarm(next_alarm);
    }
    remove_node(h);
    free(h);
    cli->status = ST_WAIT_DISCOVER;
  }
  sigprocmask(SIG_UNBLOCK, &block, NULL);
}

/*
 * Msg initializer.
 */
void init_as_failed_offer(msg_t *msg)
{
  msg->type = MSG_OFFER;
  msg->code = CODE_FAILED_OFFER;
  msg->time_to_live = 0;
  msg->ip = 0;
  msg->netmask = 0;
}

void init_as_offer(iplist_t *ip, msg_t *msg)
{
  msg->type = MSG_OFFER;
  msg->code = CODE_SUCCESS;
  msg->time_to_live = 40;
  msg->ip = ip->ip;
  msg->netmask = ip->netmask;
}

void init_as_reply(msg_t *msg, iplist_t* ip)
{
  msg->type = MSG_REPLY;
  msg->code = CODE_SUCCESS;
  msg->time_to_live = 40;
  msg->ip = ip->ip;
  msg->netmask = ip->netmask;
}

void init_as_failed_reply(msg_t *msg)
{
  msg->type = MSG_REPLY;
  msg->code = CODE_ERROR_REP;
  msg->time_to_live = 0;
  msg->ip = 0;
  msg->netmask = 0;

}

/*
 * Utility functions
 */
void init_roots()
{
  if((client_root = malloc(sizeof(node_t))) == NULL) {
    fprintf(stderr, "Failed to allocate client_root.\n");
    exit(EXIT_FAILURE);
  }
  client_root->fp = client_root->bp = client_root;
  
  if((iplist_root = malloc(sizeof(node_t))) == NULL) {
    fprintf(stderr, "Failed to allocate iplist_root.\n");
    exit(EXIT_FAILURE);
  }
  iplist_root->fp = iplist_root->bp = iplist_root;

  if((req_wait_root = malloc(sizeof(node_t))) == NULL) {
    fprintf(stderr, "Failed to allocate req_wait_root.\n");
    exit(EXIT_FAILURE);
  }
  req_wait_root->fp = req_wait_root->bp = req_wait_root;

  if((assign_root = malloc(sizeof(node_t))) == NULL) {
    fprintf(stderr, "Failed to allocate assign_root.\n");
    exit(EXIT_FAILURE);
  }
  assign_root->fp = assign_root->bp = assign_root;

  if((timeout_root = malloc(sizeof(node_t))) == NULL) {
    fprintf(stderr, "Failed to allocate timeout_root.\n");
    exit(EXIT_FAILURE);
  }
  timeout_root->fp = timeout_root->bp = timeout_root;
}

node_t* ensure_client(struct in_addr* addr, unsigned short *port)
{
  node_t *msgNode = search_client(addr, port);

  if (msgNode == NULL) {
    fprintf(stderr, "new client!!\n");
    client_t *cl;
    if ((cl = malloc(sizeof(client_t))) == NULL) {
      fprintf(stderr, "Failed to allocate memory of client_t\n");
      exit(EXIT_FAILURE);
    }
    cl->cli_adr = *addr;
    cl->cli_port = *port;
    cl->status = ST_WAIT_DISCOVER;
    if ((msgNode = new_node(cl)) == NULL) {
      fprintf(stderr, "Failed to allocate memory of node_t\n");
      exit(EXIT_FAILURE);
    }
    insert_node(client_root, msgNode);
  }
  return msgNode;
}

/*
 * State Functions
 */
void st_discover(int sd, msg_t *msg, client_t *cli)
{
  printf("Discover MSG\n");
  if(cli->status == ST_WAIT_DISCOVER) {
    msg_t offer_msg;
    node_t *ipnode;
     if((ipnode = peek_head(iplist_root)) == NULL) {
      init_as_failed_offer(&offer_msg);
      send_to(sd, &offer_msg, sizeof offer_msg, 0,
             (struct sockaddr *)&skt, sizeof skt);
    } else {
      init_as_offer(ipnode->data, &offer_msg);
      send_to(sd, &offer_msg, sizeof offer_msg, 0,
             (struct sockaddr *)&skt, sizeof skt);
      cli->status = ST_WAIT_REQUEST;

      //push to waiting list.
      req_wait_t *w;
      if ((w = malloc(sizeof(req_wait_t))) == NULL) {
        fprintf(stderr, "Failed to allocate memory of req_wait_t\n");
        exit(EXIT_FAILURE);
      }
      w->cli = cli;
      w->ip = ipnode->data;
      node_t *n;
      if((n = new_node(w)) == NULL) {
        fprintf(stderr, "Failed to allocate memory of node\n");
        exit(EXIT_FAILURE);
      }
      insert_node(req_wait_root, n);

      /*
       * Setup timeout
       */
      node_t *tnode;
      timeout_t *t;
      if ((t = malloc(sizeof(timeout_t))) == NULL) {
        fprintf(stderr, "Failed to allocate memory of timeout_t\n");
        exit(EXIT_FAILURE);
      }
      long crrtime = get_time();
      t->cli = cli;
      t->start = crrtime;
      t->exp = crrtime + TIMEOUT;
      if ((tnode = new_node(t)) == NULL) {
        fprintf(stderr, "Failed to allocat ememory of node_t\n");
        exit(EXIT_FAILURE);
      }
      if (empty(timeout_root)) {
        alarm(TIMEOUT);
      }
      insert_node(timeout_root, tnode);
    }
  } else {
    fprintf(stderr, "Illigal state\n");
  }
}

void st_request(int sd, msg_t *msg, client_t *cli)
{
  if(msg->code == CODE_ASSING_REQ) {
    if(cli->status == ST_WAIT_REQUEST) {
      node_t *w;
      if((w = search_req_wait(cli)) != NULL) {
        iplist_t *waitIp = ((req_wait_t*)w->data)->ip;
        if(waitIp->ip == msg->ip && waitIp->netmask == msg->netmask) {
          node_t *i;
          if((i = search_iplist(&msg->ip, &msg->netmask)) != NULL) {
            //Assign IP to client.
            remove_node(i);
            assign_t *a;
            if((a = malloc(sizeof(assign_t))) == NULL) {
              fprintf(stderr, "Failed to allocate memory of assign_t\n");
              exit(EXIT_FAILURE);
            }
            a->ip = i->data;
            a->cli = cli;
            node_t *n;
            if((n = new_node(a)) == NULL) {
              fprintf(stderr, "Failed to allocate memory of node_t\n");
              exit(EXIT_FAILURE);
            }
            insert_node(assign_root, n);
            char netmask_str[256];
            char ip_str[256];
            char *nstr = netmask_str;
            char *istr = ip_str;
            uint32_t_to_netmask(a->ip->netmask, nstr);
            uint32_t_to_ipstr(a->ip->ip, istr);
            printf("Assign IP: %s(%s) to client:(%s)(%d)\n",
                   ip_str,
                   netmask_str,
                   inet_ntoa(cli->cli_adr),
                   ntohs(cli->cli_port));
            //Return reply message.
            msg_t reply_msg;
            init_as_reply(&reply_msg, i->data);
            send_to(sd, &reply_msg, sizeof reply_msg, 0,
                   (struct sockaddr *)&skt, sizeof skt);
            cli->status = ST_WAIT_REQ_OR_RELEASE;
            cli->lease = 40;
            reflesh_timeout(cli, 40, 1);
          } else {
            //Already assigned.
            msg_t reply_msg;
            init_as_failed_reply(&reply_msg);
            send_to(sd, &reply_msg, sizeof reply_msg, 0,
                    (struct sockaddr *)&skt, sizeof skt);
          }
        } else {
          fprintf(stderr, "requested ip doesn't match waiting ip\n");
        }
      } else {
        fprintf(stderr, "Illigal state\n");
      }
    } else {
      fprintf(stderr, "Illigal state\n");
    }
  } else if(msg->code == CODE_EXT_REQ) {
    if(cli->status == ST_WAIT_REQ_OR_RELEASE) {
      //Check Requested IP.
      node_t *a;
      if((a = search_assign(cli)) != NULL) {
        iplist_t *i = ((assign_t*)a->data)->ip;
        if(i->ip == msg->ip && i->netmask == msg->netmask) {
          //Return reply message.
          msg_t reply_msg;
          init_as_reply(&reply_msg, i);
          send_to(sd, &reply_msg, sizeof reply_msg, 0,
                 (struct sockaddr *)&skt, sizeof skt);
          //Reflesh lease.
          cli->lease = 40;
          reflesh_timeout(cli, 40, 1);
        } else {
          //Error state. unassigned ip requested.
        }
      } else {
        //Return errror.
      }
    } else {
      fprintf(stderr, "Illigal state\n");
    }
  } else {
    fprintf(stderr, "Illigal state\n");
  }
}

void st_release(int sd, msg_t *msg, client_t *cli)
{
  if(cli->status == ST_WAIT_REQ_OR_RELEASE) {
    //Release IP.
    node_t *a;
    if((a = search_assign(cli)) != NULL) {
      node_t *i;
      if((i = new_node(((assign_t*)a->data)->ip)) == NULL) {
        fprintf(stderr, "Failed to allocate memory of node_t\n");
        exit(EXIT_FAILURE);
      }
      insert_node(iplist_root, i);
      remove_node(a);
      free(a);
      struct in_addr ip_addr;
      assign_t *as = a->data;
      ip_addr.s_addr = as->ip->ip;
      fprintf(stderr, "IP Released: %s\n", inet_ntoa(ip_addr));
      reflesh_timeout(cli, 0, 0);
    } else {
      fprintf(stderr, "298 Illigal state\n");
    }
  } else {
    fprintf(stderr, "301 Illigal state\n");
  }
}

void st_illigal(int sd, msg_t *msg, client_t *cli)
{
  fprintf(stderr, "Illigal state message\n");
  fprintf(stderr, "Client state is %d\n", cli->status);
  fprintf(stderr, "Message type is %d\n", msg->type);
}
