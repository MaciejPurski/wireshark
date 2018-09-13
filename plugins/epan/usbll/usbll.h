#ifndef H_USBLL
#define H_USBLL

#include <epan/conversation_table.h>

#define PID_SOF     0xA5
#define PID_DATA0   0xC3
#define PID_DATA1   0x4B
#define PID_DATA2   0x87
#define PID_MDATA   0x0f
#define PID_OUT     0xE1
#define PID_IN      0x69
#define PID_SETUP   0x2D
#define PID_ACK     0xD2
#define PID_NAK     0x5A
#define PID_STALL   0x1E
#define PID_NYET    0x96
#define PID_PRE_ERR 0x3c
#define PID_SPLIT   0x78
#define PID_PING    0xB4

#define TOKEN_PACKET(pid)   pid == PID_SETUP || pid == PID_IN || pid == PID_OUT || pid == PID_PING

#define DATA_PACKET(pid)    pid == PID_DATA0 || pid == PID_DATA1 || pid == PID_DATA0 || \
                            pid == PID_MDATA

#define HANDSHAKE_PACKET(pid)   pid == PID_ACK || pid == PID_NAK || pid == PID_STALL || \
                                pid == PID_NYET || pid == PID_PRE_ERR

#define SOF_PACKET(pid)         pid == PID_SOF




#endif
