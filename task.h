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
#include "utils.h"

const uint32_t RFC_5389_MAGIC_COOKIE = 0x2112A442;
const int NUM_BYTES_STUN_HEADER = 20;

const quint16 DEFAULT_DOMAIN_SERVER_PORT = 40102;
const int HIFI_INITIAL_UPDATE_INTERVAL_MSEC = 250;
const int HIFI_PING_UPDATE_INTERVAL_MSEC = 1000;
const int HIFI_NUM_INITIAL_REQUESTS_BEFORE_FAIL = 10;
const int NUM_BYTES_RFC4122_UUID = 16;

typedef quint8 NodeType_t;

namespace NodeType {
    const NodeType_t DomainServer = 'D';
    const NodeType_t EntityServer = 'o'; // was ModelServer
    const NodeType_t Agent = 'I';
    const NodeType_t AudioMixer = 'M';
    const NodeType_t AvatarMixer = 'W';
    const NodeType_t AssetServer = 'A';
    const NodeType_t MessagesMixer = 'm';
    const NodeType_t EntityScriptServer = 'S';
    const NodeType_t UpstreamAudioMixer = 'B';
    const NodeType_t UpstreamAvatarMixer = 'C';
    const NodeType_t DownstreamAudioMixer = 'a';
    const NodeType_t DownstreamAvatarMixer = 'w';
    const NodeType_t Unassigned = 1;

    const QString& getNodeTypeName(NodeType_t nodeType);
    bool isUpstream(NodeType_t nodeType);
    bool isDownstream(NodeType_t nodeType);
    NodeType_t upstreamType(NodeType_t primaryType);
    NodeType_t downstreamType(NodeType_t primaryType);


    NodeType_t fromString(QString type);
}

typedef QSet<NodeType_t> NodeSet;

enum class Permission {
    none = 0,
    canConnectToDomain = 1,
    canAdjustLocks = 2,
    canRezPermanentEntities = 4,
    canRezTemporaryEntities = 8,
    canWriteToAssetServer = 16,
    canConnectPastMaxCapacity = 32,
    canKick = 64,
    canReplaceDomainContent = 128,
    canRezPermanentCertifiedEntities = 256,
    canRezTemporaryCertifiedEntities = 512
};
Q_DECLARE_FLAGS(Permissions, Permission)

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

public slots:

    void run();
    void readPendingDatagrams(QString f);
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

    QSignalMapper * signal_mapper;

    QUdpSocket * client_socket;
    QHostAddress client_address;
    quint16 client_port;

    QUdpSocket * server_socket;
    QHostAddress server_address;
    quint16 server_port;

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
};
#endif // TASK_H
