#ifndef __MSG_H__
#define __MSG_H__

#include <arpa/inet.h>

#define MSG_DISCOVER 1
#define MSG_OFFER 2
#define MSG_REQUEST 3
#define MSG_REPLY 4
#define MSG_RELEASE 5

#define CODE_SUCCESS 0
#define CODE_FAILED_OFFER 129
#define CODE_ASSING_REQ 10
#define CODE_EXT_REQ 11
#define CODE_ERROR_REP 130

typedef struct {
  uint8_t type;
  uint8_t code;
  uint16_t time_to_live;
  uint32_t ip;
  uint32_t netmask;
} msg_t;

void outputMsg(msg_t *);

#endif
