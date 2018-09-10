#ifndef TASK_H
#define TASK_H

#include <QObject>
#include <QDebug>
#include <QtNetwork>
#include <QString>
#include <QSignalMapper>
#include <QThread>
#include <QTimer>
#include <QUuid>

#include "packet.h"

const uint32_t RFC_5389_MAGIC_COOKIE = 0x2112A442;
const int NUM_BYTES_STUN_HEADER = 20;

const quint16 DEFAULT_DOMAIN_SERVER_PORT = 40102;
const int HIFI_INITIAL_UPDATE_INTERVAL_MSEC = 250;
const int HIFI_NUM_INITIAL_REQUESTS_BEFORE_FAIL = 10;

class Task : public QObject
{
    Q_OBJECT

public:

    Task(QObject *parent = 0);
    void processCommandLineArguments(int argc, char * argv[]);
    void handleLookupResult(const QHostInfo& hostInfo, QHostAddress * addr);

    void makeStunRequestPacket(char * stunRequestPacket);

public slots:

    void run();
    void readPendingDatagrams(QString f);
    void startIce();
    void startStun();
    void startDomainConnect();

    void sendStunRequest();
    void parseStunResponse();
    void sendIceRequest();
    void parseIceResponse();
    void sendDomainConnectRequest();
    void parseDomainConnectResponse();

    void domainRequestFinished();

signals:

    void stunFinished();
    void iceFinished();
    void finished();

private:

    QString uuidStringWithoutCurlyBraces(const QUuid& uuid) {
        QString uuidStringNoBraces = uuid.toString().mid(1, uuid.toString().length() - 2);
        return uuidStringNoBraces;
    }

    QSignalMapper * signal_mapper;

    QUdpSocket * client_socket;
    QHostAddress client_address;
    quint16 client_port;

    QUdpSocket * server_socket;
    QHostAddress server_address;
    quint16 server_port;

    QUdpSocket * hifi_socket;
    QTimer * hifi_response_timer;

    QHostAddress public_address;
    quint16 public_port;
    QHostAddress local_address;
    quint16 local_port;

    QString stun_server_hostname;
    quint16 stun_server_port;

    QString ice_server_hostname;
    QHostAddress ice_server_address;
    quint16 ice_server_port;

    QUuid ice_client_id;

    bool has_completed_current_request;
    int num_requests;

    QString domain_name;
    QUuid domain_id;
    QHostAddress domain_public_address;
    quint16 domain_public_port;
    QHostAddress domain_local_address;
    quint16 domain_local_port;

    bool use_custom_ice_server;

    QNetworkReply * domain_reply;
    QByteArray domain_reply_contents;
    bool finished_domain_id_request;
};
#endif // TASK_H
