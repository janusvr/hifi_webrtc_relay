#ifndef NODE_H
#define NODE_H

#include <stdint.h>
#include <QObject>
#include <QtNetwork>

#include "hmacauth.h"
#include "packet.h"
#include "utils.h"

#define SPDLOG_DISABLED

#include <rtcdcpp/PeerConnection.hpp>

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

class Node : public QObject
{
    Q_OBJECT

public:
    Node();
    ~Node();

    NodeType_t GetNodeType() {return node_type;}

    void SetSequenceNumber(uint32_t s) { if (s > sequence_number) sequence_number = s;}

    void SetNodeID(QUuid n);
    void SetNodeType(NodeType_t n);
    void SetPublicAddress(QHostAddress a, quint16 p);
    void SetLocalAddress(QHostAddress a, quint16 p);
    void SetSessionLocalID(quint16 s);
    void SetDomainSessionLocalID(quint16 s);
    void SetIsReplicated(bool b);
    void SetConnectionSecret(QUuid c);
    void SetPermissions(Permissions p);

    void SetDataChannel(std::shared_ptr<rtcdcpp::DataChannel> channel);

    void ActivatePublicSocket(QSharedPointer<QUdpSocket> s);

    void Ping(quint8 ping_type);
    void PingReply(Packet * packet, QHostAddress sender, quint16 sender_port);
    void SetNegotiatedAudioFormat(bool b);
    void StartNegotiateAudioFormat();

    void SendMessageToServer(QString message) {node_socket->write(message.toLatin1());}
    void SendMessageToServer(QByteArray message) {node_socket->write(message);}

    void SendMessageToClient(QString message) {data_channel->SendString(message.toStdString());}
    void SendMessageToClient(QByteArray message) {data_channel->SendBinary((const uint8_t *) message.data(), message.size());}

    bool CheckNodeAddress(QHostAddress a, quint16 p);

    void HandleControlPacket(Packet * control_packet);
    void SendHandshakeRequest();
    bool GetHasReceivedHandshakeAck() {return has_received_handshake_ack;}

Q_SIGNALS:
    void Disconnected();
    void HandshakeAckReceived();

public Q_SLOTS:
    void SendNegotiateAudioFormat();
    void SendPing();

private:
    QUuid node_id;
    NodeType_t node_type;
    QHostAddress public_address;
    quint16 public_port;
    QHostAddress local_address;
    quint16 local_port;
    quint16 session_local_id;
    bool is_replicated;
    QUuid connection_secret;
    Permissions permissions;

    quint16 domain_session_local_id;

    std::unique_ptr<HMACAuth> authenticate_hash;

    QSharedPointer<QUdpSocket> node_socket;

    QTimer * hifi_response_timer;

    uint32_t sequence_number;
    uint32_t last_sequence_number;

    bool started_negotiating_audio_format;
    bool negotiated_audio_format;
    int num_requests;

    std::shared_ptr<rtcdcpp::DataChannel> data_channel;

    std::unique_ptr<Packet> ack_packet;
    std::unique_ptr<Packet>  handshake_ack;
    uint32_t last_ack_received;
    bool has_received_handshake;
    bool has_received_handshake_ack;
    bool did_request_handshake;
};

#endif // NODE_H
