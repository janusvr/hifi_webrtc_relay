#include <random>

#include "node.h"

Node::Node()
{
    authenticate_hash = nullptr;
    num_requests = 0;
}

Node::~Node()
{
    if (node_socket) {
        node_socket.clear();
    }
}

void Node::SetNodeID(QUuid n)
{
    node_id = n;
}

void Node::SetNodeType(NodeType_t n)
{
    node_type = n;
}

void Node::SetPublicAddress(QHostAddress a, quint16 p)
{
    public_address = a;
    public_port = p;
}

void Node::SetLocalAddress(QHostAddress a, quint16 p)
{
    local_address = a;
    local_port = p;
}

void Node::SetSessionLocalID(quint16 s)
{
    session_local_id = s;
}

void Node::SetDomainSessionLocalID(quint16 s)
{
    domain_session_local_id = s;
}

void Node::SetIsReplicated(bool b)
{
    is_replicated = b;
}

void Node::SetConnectionSecret(QUuid c)
{
    if (connection_secret == c) {
        return;
    }

    if (!authenticate_hash) {
        authenticate_hash.reset(new HMACAuth());
    }

    connection_secret = c;
    authenticate_hash->SetKey(c);
}

void Node::SetPermissions(Permissions p)
{
    permissions = p;
}

void Node::ActivatePublicSocket(QSharedPointer<QUdpSocket> s)
{
    node_socket = s;
}

bool Node::CheckNodeAddress(QHostAddress a, quint16 p)
{
    //qDebug() << a.toIPv4Address()<< public_address.toIPv4Address() << p << public_port;
    return (a.toIPv4Address() == public_address.toIPv4Address() && p == public_port);
}
