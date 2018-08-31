#ifndef TASK_H
#define TASK_H

#include <QObject>
#include <QDebug>
#include <QHostInfo>
#include <QtNetwork>
#include <QString>
#include <QSignalMapper>
#include <QThread>
#include <QTimer>
#include <QUuid>

const uint32_t RFC_5389_MAGIC_COOKIE = 0x2112A442;
const int NUM_BYTES_STUN_HEADER = 20;

const quint16 DEFAULT_DOMAIN_SERVER_PORT = 40102;

class Task : public QObject
{
    Q_OBJECT

public:

    Task(QObject *parent = 0);
    void ProcessCommandLineArguments(int argc, char * argv[]);
    void handleLookupResult(const QHostInfo& hostInfo, QHostAddress * addr);

    void makeStunRequestPacket(char * stunRequestPacket);
    void makeIceRequestPacket(char * iceRequestPacket);

    QHostAddress getGuessedLocalAddress();
    void connectedForLocalSocketTest();
    void updateLocalSocket();

public slots:

    void run();
    void readPendingDatagrams(QString f);
    void startIce();

    void sendStunRequest();
    void parseStunResponse();
    void sendIceRequest();
    void parseIceResponse();

    void errorTestingLocalSocket();

signals:

    void stunFinished();
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

    QUdpSocket * ice_stun_socket;

    QHostAddress public_address;
    quint16 public_port;
    QHostAddress local_address;

    QHostAddress stun_server_address;
    QString stun_server_hostname;
    quint16 stun_server_port;

    QHostAddress ice_server_address;
    QString ice_server_hostname;
    quint16 ice_server_port;

    QTimer * stunResponseTimer;
    bool hasCompletedInitialStun;
    int numInitialStunRequests;

    QUuid iceClientID;

    QTimer * iceResponseTimer;
    bool hasCompletedInitialIce;
    int numInitialIceRequests;

    QNetworkAccessManager * networkAccessManager;

    QByteArray sessionID;
    QUuid domain_id;

    bool hasTCPCheckedLocalSocket;

    /*const int ICE_HEARBEAT_INTERVAL_MSECS = 2 * 1000;
    const int MAX_ICE_CONNECTION_ATTEMPTS = 5;

    const int UDP_PUNCH_PING_INTERVAL_MS = 25;*/

};
#endif // TASK_H
