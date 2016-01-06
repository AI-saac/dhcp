#ifndef __SOCK_UTIL_H__
#define __SOCK_UTIL_H__

#include <sys/socket.h>

ssize_t send_to(int socket, const void *buffer, size_t length,
                int flags, const struct sockaddr *dest_addr, socklen_t dest_len);

ssize_t recv_from(int socket, void *restrict buffer, size_t length,
                  int flags, struct sockaddr *restrict address,
                  socklen_t *restrict address_len);

#endif
