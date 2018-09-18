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
#include "node.h"
#include "utils.h"

class Task : public QObject
{
    Q_OBJECT

public:

    Task(QObject *parent = 0);
    void processCommandLineArguments(int argc, char * argv[]);
    void handleLookupResult(const QHostInfo& hostInfo, QHostAddress * addr);

    void makeStunRequestPacket(char * stunRequestPacket);
    void sendIcePing(quint8 pingType);
    void sendIcePingReply(Packet * icePing);

    void parseNodeFromPacketStream(QDataStream& packetStream);

public slots:

    void relayToServer();

    void run();
    void startIce();
    void startStun();
    void startDomainIcePing();
    void startDomainConnect();

    void sendStunRequest();
    void parseStunResponse();
    void sendIceRequest();
    void parseIceResponse();
    void sendDomainIcePing();
    void sendDomainConnectRequest();
    void parseDomainResponse();

    void domainRequestFinished();

signals:

    void stunFinished();
    void iceFinished();
    void domainPinged();
    void domainConnected();
    void finished();

private:

    QString uuidStringWithoutCurlyBraces(const QUuid& uuid) {
        QString uuidStringNoBraces = uuid.toString().mid(1, uuid.toString().length() - 2);
        return uuidStringNoBraces;
    }

    QUdpSocket * client_socket;
    QHostAddress client_address;
    quint16 client_port;

    QUdpSocket * hifi_socket;
    QTimer * hifi_ping_timer;
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
    bool domain_connected;
    uint32_t num_requests;

    QString domain_name;
    QString domain_place_name;
    QUuid domain_id;
    QHostAddress domain_public_address;
    quint16 domain_public_port;
    QHostAddress domain_local_address;
    quint16 domain_local_port;

    bool use_custom_ice_server;

    QNetworkReply * domain_reply;
    QByteArray domain_reply_contents;
    bool finished_domain_id_request;

    std::atomic<NodeType_t> owner_type;
    NodeSet node_types_of_interest;

    bool started_domain_connect;
    uint32_t sequence_number;

    QUuid session_id;
    quint16 local_id;

    Permissions permissions;

    Node * asset_server;
    Node * audio_mixer;
    Node * avatar_mixer;
    Node * messages_mixer;
    Node * entity_server;
    Node * entity_script_server;

};
#endif // TASK_H
