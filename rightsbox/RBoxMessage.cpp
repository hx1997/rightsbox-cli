//
// Created by hx1997 on 2018/3/7.
//

#include <cstdio>
#include <windows.h>

#include "RBoxMessage.h"

// Issue an app-wide message
int IssueMessage(const char *szMsg, MESSAGETYPE MsgType) {
    switch (MsgType) {
        case MSGTYPE_INFO:
            fprintf(stdout, "[INFO]\t%s\r\n", szMsg);
            break;
        case MSGTYPE_WARNING:
            fprintf(stderr, "[WARNING]\t%s\r\n", szMsg);
            break;
        case MSGTYPE_ERROR:
            fprintf(stderr, "[ERROR]\t%s\r\n", szMsg);
            break;
        default:
            return -1;
    }

    return 0;
}