#ifndef TASK_H
#define TASK_H

#include <QObject>
#include <QtWebSockets>
#include <QDebug>
#include <QtNetwork>
#include <QString>
#include <QThread>
#include <QTimer>
#include <QUuid>

#define SPDLOG_DISABLED

#ifdef Q_OS_WIN
#include <winsock2.h>
#include <WS2tcpip.h>
#endif //Q_OS_WIN

#ifdef Q_OS_UNIX
#include <sys/socket.h>
#include <netinet/in.h>
#endif //Q_OS_UNIX

#include "packet.h"
#include "node.h"
#include "utils.h"
#include "hificonnection.h"

#include "portableendian.h"

#include <rtcdcpp/PeerConnection.hpp>

class Task : public QObject
{
    Q_OBJECT

public:

    Task(QObject *parent = 0);
    ~Task();

    void ProcessCommandLineArguments(int argc, char * argv[]);
    void HandleLookupResult(const QHostInfo& hostInfo, QString addr_type);

public Q_SLOTS:

    void run();

    void DomainRequestFinished();

    void Connect();
    void Disconnect();
    void ServerConnected();
    void ServerDisconnected();

    void DisconnectHifiConnection();

Q_SIGNALS:

    void Finished();

private:

    QNetworkReply * domain_reply;
    QByteArray domain_reply_contents;

    quint16 signaling_server_port;
    QWebSocketServer * signaling_server;

    QList<HifiConnection *> hifi_connections;
};
#endif // TASK_H
