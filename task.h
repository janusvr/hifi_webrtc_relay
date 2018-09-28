#ifndef TASK_H
#define TASK_H

#include <QObject>
#include <QtWebSockets>
#include <QDebug>
#include <QtNetwork>
#include <QString>
#include <QSignalMapper>
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

#include "portableendian.h"

#include <rtcdcpp/PeerConnection.hpp>

class Task : public QObject
{
    Q_OBJECT

public:

    Task(QObject *parent = 0);
    ~Task();

    void processCommandLineArguments(int argc, char * argv[]);
    void handleLookupResult(const QHostInfo& hostInfo, QHostAddress * addr);

    void makeStunRequestPacket(char * stunRequestPacket);
    void sendIcePing(quint8 pingType);
    void sendIcePingReply(Packet * icePing);

    void parseNodeFromPacketStream(QDataStream& packetStream);

    void SetDomainServerDC(std::shared_ptr<rtcdcpp::DataChannel> d) {domain_server_dc = d;}
    void SetAudioMixerDC(std::shared_ptr<rtcdcpp::DataChannel> d) {audio_mixer_dc = d;}
    void SetAvatarMixerDC(std::shared_ptr<rtcdcpp::DataChannel> d) {avatar_mixer_dc = d;}
    void SetMessagesMixerDC(std::shared_ptr<rtcdcpp::DataChannel> d) {messages_mixer_dc = d;}
    void SetAssetServerDC(std::shared_ptr<rtcdcpp::DataChannel> d) {asset_server_dc = d;}
    void SetEntityServerDC(std::shared_ptr<rtcdcpp::DataChannel> d) {entity_server_dc = d;}
    void SetEntityScriptServerDC(std::shared_ptr<rtcdcpp::DataChannel> d) {entity_script_server_dc = d;}

    bool DataChannelsReady(){
        return (domain_server_dc && audio_mixer_dc && avatar_mixer_dc && messages_mixer_dc && entity_server_dc && entity_script_server_dc && asset_server_dc);
    }

    void SendDomainServerMessage(QString message) {hifi_socket->write(message.toLatin1());}
    void SendDomainServerMessage(QByteArray message) {hifi_socket->write(message);}

    void SendDomainServerDCMessage(QString message) {domain_server_dc->SendString(message.toStdString());}
    void SendDomainServerDCMessage(QByteArray message) {domain_server_dc->SendBinary((const uint8_t *) message.data(), message.size());}

    QList<QWebSocket *> GetClientSockets() {return client_sockets;}

public Q_SLOTS:

    void HifiConnect();

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

    void Connect();
    void Disconnect();
    void ServerConnected();
    void ServerDisconnected();
    void ClientMessageReceived(const QString &message);
    void ClientDisconnected();

Q_SIGNALS:

    void WebRTCConnectionReady();
    void finished();

private:

    QString uuidStringWithoutCurlyBraces(const QUuid& uuid) {
        QString uuidStringNoBraces = uuid.toString().mid(1, uuid.toString().length() - 2);
        return uuidStringNoBraces;
    }

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

    quint16 signal_server_port;

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

    std::shared_ptr<rtcdcpp::PeerConnection> remote_peer_connection;

    QWebSocketServer * signaling_server;

    std::shared_ptr<rtcdcpp::DataChannel> domain_server_dc;
    std::shared_ptr<rtcdcpp::DataChannel> audio_mixer_dc;
    std::shared_ptr<rtcdcpp::DataChannel> avatar_mixer_dc;
    std::shared_ptr<rtcdcpp::DataChannel> messages_mixer_dc;
    std::shared_ptr<rtcdcpp::DataChannel> entity_server_dc;
    std::shared_ptr<rtcdcpp::DataChannel> entity_script_server_dc;
    std::shared_ptr<rtcdcpp::DataChannel> asset_server_dc;

    QList<QWebSocket *> client_sockets;
};
#endif // TASK_H
