#ifndef HIFICONNECTION_H
#define HIFICONNECTION_H

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

class HifiConnection : public QObject
{
    Q_OBJECT

public:
    HifiConnection(QWebSocket * s);
    ~HifiConnection();

    void HandleLookupResult(const QHostInfo& hostInfo, QString addr_type);

    void UpdateLocalSocket();
    QHostAddress GetGuessedLocalAddress();

    void ClearDataChannel() {
        std::function<void(std::string)> onErrorCallback = [](std::string x) { ; };
        data_channel->SetOnErrorCallback(onErrorCallback);
        std::function<void(rtcdcpp::ChunkPtr)> onBinaryMessageCallback = [](rtcdcpp::ChunkPtr data) { ; };
        data_channel->SetOnBinaryMsgCallback(onBinaryMessageCallback);
        std::function<void()> onClosed = []() { ; };
        data_channel->SetOnClosedCallback(onClosed);

        data_channel = nullptr;
    }

    void Stop();

    void SendIcePing(uint32_t s, quint8 ping_type);
    void SendIcePingReply(uint32_t s, quint8 ping_type);
    void SendDomainCheckInRequest(uint32_t s = 0);

    void ParseNodeFromPacketStream(QDataStream& packet_stream);

    void SendServerMessage(QByteArray message, QHostAddress address, quint16 port) {if (hifi_socket) hifi_socket->writeDatagram(message, address, port);}
    void SendServerMessage(char * message, int len, QHostAddress address, quint16 port) {if (hifi_socket) hifi_socket->writeDatagram(message, len, address, port);}

    void SendClientMessageFromNode(NodeType_t node_type, QByteArray data) {
        data.push_front((char) node_type);
        SendClientMessage(data.data(), data.size());
    }
    void SendClientMessage(char * data, int len) {if (data_channel) data_channel->SendBinary((const uint8_t *) data, len);}

    Node * GetNodeFromAddress(QHostAddress sender, quint16 sender_port);

    void ParseDatagram(QByteArray response_packet);

Q_SIGNALS:

    void Disconnected();
    void WebRTCConnectionReady();

    void StunFinished();
    void IceFinished();

public Q_SLOTS:

    void Timeout();

    void ConnectedForLocalSocketTest();
    void ErrorTestingLocalSocket();

    void DomainRequestFinished();

    void StartIce();
    void StartStun();
    void StartDomainConnect();

    void SendStunRequest();
    void SendIceRequest();
    void SendDomainCheckIn();
    void ParseHifiResponse();

    void ClientMessageReceived(const QString &message);
    void ServerDisconnected();

private:

    QString uuidStringWithoutCurlyBraces(const QUuid& uuid) {
        QString uuid_string_no_braces = uuid.toString().mid(1, uuid.toString().length() - 2);
        return uuid_string_no_braces;
    }

    bool has_tcp_checked_local_socket;

    QUdpSocket * hifi_socket;
    QTimer * timeout_timer;
    QTimer * stun_response_timer;
    QTimer * ice_response_timer;
    QTimer * hifi_response_timer;

    QHostAddress public_address;
    quint16 public_port;
    QHostAddress local_address;
    quint16 local_port;

    QUuid ice_client_id;

    bool started_hifi_connect;

    bool has_completed_current_request;
    bool domain_connected;
    uint32_t num_requests;

    QHostAddress domain_public_address;
    quint16 domain_public_port;
    QHostAddress domain_local_address;
    quint16 domain_local_port;

    std::atomic<NodeType_t> owner_type;
    NodeSet node_types_of_interest;

    bool started_domain_connect;

    QUuid session_id;
    quint16 local_id;

    Permissions permissions;

    Node * asset_server;
    Node * audio_mixer;
    Node * avatar_mixer;
    Node * messages_mixer;
    Node * entity_server;
    Node * entity_script_server;

    QWebSocket * client_socket;
    std::shared_ptr<rtcdcpp::PeerConnection> remote_peer_connection;

    std::shared_ptr<rtcdcpp::DataChannel> data_channel;

    bool finished_domain_id_request;
    QString domain_name;
    QString domain_place_name;
    QUuid domain_id;

    QString stun_server_hostname;
    QHostAddress stun_server_address;
    quint16 stun_server_port;

    QString ice_server_hostname;
    QHostAddress ice_server_address;
    quint16 ice_server_port;

    quint64 client_timestamp;
    quint64 server_timestamp;
};

#endif // HIFICONNECTION_H
