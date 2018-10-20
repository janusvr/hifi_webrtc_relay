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

class PendingDatagram: public QObject
{
    Q_OBJECT

public:
    PendingDatagram(QByteArray b, QHostAddress a, quint16 p)
    {
        data = b;
        sender = a;
        sender_port = p;
    }
    ~PendingDatagram() {}

    QByteArray GetDatagram() {return data;}
    QHostAddress GetSender() {return sender;}
    quint16 GetSenderPort() {return sender_port;}

private:
    QByteArray data;
    QHostAddress sender;
    quint16 sender_port;
};

class HifiConnection : public QObject
{
    Q_OBJECT

public:
    HifiConnection(QWebSocket * s);
    ~HifiConnection();

    void HandleLookupResult(const QHostInfo& hostInfo, QString addr_type);

    void UpdateLocalSocket();
    QHostAddress GetGuessedLocalAddress();

    void Stop();

    void SendIcePing(quint8 ping_type);
    void SendIcePingReply(Packet * ice_ping, QHostAddress sender, quint16 sender_port);

    void ParseNodeFromPacketStream(QDataStream& packet_stream);

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

    void SendDomainServerMessage(QString message) {hifi_socket->writeDatagram(message.toLatin1(), domain_public_address, domain_public_port);}
    void SendDomainServerMessage(QByteArray message) {hifi_socket->writeDatagram(message, domain_public_address, domain_public_port);}

    void SendDomainServerDCMessage(QString message) {domain_server_dc->SendString(message.toStdString());}
    void SendDomainServerDCMessage(QByteArray message) {domain_server_dc->SendBinary((const uint8_t *) message.data(), message.size());}

    Node * GetNodeFromAddress(QHostAddress sender, quint16 sender_port);

    void SendHandshakeRequest();
    void SendDomainListRequest();

    void ParseDatagram(QByteArray response_packet, QHostAddress sender, quint16 sender_port);

Q_SIGNALS:

    void Disconnected();
    void WebRTCConnectionReady();

    void StartHifiConnection();
    void StunFinished();
    void IceFinished();
    void DomainIcePingFinished();

    void DomainServerHasReceivedHandshakeAck();

public Q_SLOTS:

    void ConnectedForLocalSocketTest();
    void ErrorTestingLocalSocket();

    void DomainRequestFinished();

    void HifiConnect();

    void StartIce();
    void StartStun();
    void StartDomainIcePing();
    void StartDomainConnect();

    void SendStunRequest();
    void SendIceRequest();
    void SendDomainIcePing();
    void SendDomainConnectRequest();
    void ParseHifiResponse();
    void ParsePendingDatagrams();

    void ClientMessageReceived(const QString &message);
    void ClientDisconnected();
    void ServerDisconnected();
    void NodeDisconnected();

private:

    QString uuidStringWithoutCurlyBraces(const QUuid& uuid) {
        QString uuid_string_no_braces = uuid.toString().mid(1, uuid.toString().length() - 2);
        return uuid_string_no_braces;
    }

    QNetworkReply * domain_reply;
    QByteArray domain_reply_contents;

    bool has_tcp_checked_local_socket;

    QSharedPointer<QUdpSocket> hifi_socket;
    QTimer * hifi_ping_timer;
    QTimer * stun_response_timer;
    QTimer * ice_response_timer;
    QTimer * hifi_response_timer;

    QHostAddress public_address;
    quint16 public_port;
    QHostAddress local_address;
    quint16 local_port;

    QUuid ice_client_id;

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
    uint32_t sequence_number;
    uint32_t last_sequence_number;

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

    std::shared_ptr<rtcdcpp::DataChannel> domain_server_dc;
    std::shared_ptr<rtcdcpp::DataChannel> audio_mixer_dc;
    std::shared_ptr<rtcdcpp::DataChannel> avatar_mixer_dc;
    std::shared_ptr<rtcdcpp::DataChannel> messages_mixer_dc;
    std::shared_ptr<rtcdcpp::DataChannel> entity_server_dc;
    std::shared_ptr<rtcdcpp::DataChannel> entity_script_server_dc;
    std::shared_ptr<rtcdcpp::DataChannel> asset_server_dc;

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

    bool pinged;
    bool pingreplied;

    std::unique_ptr<Packet> ack_packet;
    std::unique_ptr<Packet>  handshake_ack;
    uint32_t last_ack_received;
    bool has_received_handshake;
    bool has_received_handshake_ack;
    bool did_request_handshake;

    QList <PendingDatagram *> pending_datagrams;
};

#endif // HIFICONNECTION_H
