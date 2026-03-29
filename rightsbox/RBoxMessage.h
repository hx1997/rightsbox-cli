//
// Created by hx1997 on 2018/3/7.
//

#ifndef RIGHTSBOX_CLI_RBOXMESSAGE_H
#define RIGHTSBOX_CLI_RBOXMESSAGE_H

typedef enum {
    MSGTYPE_INFO,
    MSGTYPE_WARNING,
    MSGTYPE_ERROR
} MESSAGETYPE;

int IssueMessage(const char *szMsg, MESSAGETYPE MsgType);

#endif //RIGHTSBOX_CLI_RBOXMESSAGE_H
