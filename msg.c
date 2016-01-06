#include <stdio.h>
#include "msg.h"

void outputMsg(msg_t* msg)
{
    printf("---- msg ----\n");
    printf("type:\t%0x\n", msg->type);
    printf("code:\t%0x\n", msg->code);
    printf("time_to_live:\t%0x\n", msg->time_to_live);
    printf("ip:\t%0x\n", msg->ip);
    printf("netmask:\t%0x\n", msg->netmask);
    printf("-------------\n");
}
