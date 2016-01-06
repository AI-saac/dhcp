#include <stdio.h>
#include <stdlib.h>
#include "sock_util.h"
#include "msg.h"

ssize_t send_to(int socket, const void *buffer, size_t length,
                int flags, const struct sockaddr *dest_addr, socklen_t dest_len)
{
  ssize_t res;
  if ((res = sendto(socket, buffer, length, flags, dest_addr, dest_len)) < 0) {
    perror("sendto");
    exit(EXIT_FAILURE);
  }
  printf("Sending msg to: %s(%d)\n",
         inet_ntoa(((struct sockaddr_in*)dest_addr)->sin_addr),
         ntohs(((struct sockaddr_in*)dest_addr)->sin_port));
  outputMsg((msg_t*)buffer);
  return res;
}

ssize_t recv_from(int socket, void *restrict buffer, size_t length,
                  int flags, struct sockaddr *restrict address,
                  socklen_t *restrict address_len)
{
  ssize_t res;
  if ((res = recvfrom(socket, buffer, length, flags, address, address_len)) < 0) {
    perror("recvfrom");
    exit(EXIT_FAILURE);
  }
  printf("Recieve msg from: %s(%d)\n",
           inet_ntoa(((struct sockaddr_in*)address)->sin_addr),
           ntohs(((struct sockaddr_in*)address)->sin_port));
  outputMsg((msg_t*)buffer);
  return res;
}
