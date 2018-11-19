#ifndef NODE_H
#define NODE_H

#include <stdint.h>
#include <QObject>
#include <QtNetwork>

#include "hmacauth.h"
#include "packet.h"
#include "utils.h"

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

    void SetNodeID(QUuid n);
    void SetNodeType(NodeType_t n);
    void SetPublicAddress(QHostAddress a, quint16 p);
    void SetLocalAddress(QHostAddress a, quint16 p);
    void SetSessionLocalID(quint16 s);
    void SetDomainSessionLocalID(quint16 s);
    void SetIsReplicated(bool b);
    void SetConnectionSecret(QUuid c);
    void SetPermissions(Permissions p);

    QHostAddress GetPublicAddress();
    quint16 GetPublicPort();
    QHostAddress GetLocalAddress();
    quint16 GetLocalPort();

    bool CheckNodeAddress(QHostAddress a, quint16 p);

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

    QTimer * hifi_response_timer;

    int num_requests;
};

#endif // NODE_H
