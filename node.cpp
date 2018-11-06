#include <random>

#include "node.h"

Node::Node()
{
    authenticate_hash = nullptr;
    num_requests = 0;

    static std::random_device rd;
    static std::mt19937 generator(rd());
    static std::uniform_int_distribution<> distribution(0, 0x07FFFFFF);
    sequence_number = distribution(generator);
    initial_sequence_number = sequence_number;
    initial_receive_sequence_number = 0;
    last_sequence_number = 0;
    last_receive_sequence_number = 0;

    has_received_handshake_ack = false;
    did_request_handshake = false;

    static const int ACK_PACKET_PAYLOAD_BYTES = sizeof(uint32_t);
    static const int HANDSHAKE_ACK_PAYLOAD_BYTES = sizeof(uint32_t);
    ack_packet = Packet::CreateControl(sequence_number, ControlType::ACK, ACK_PACKET_PAYLOAD_BYTES);
    //QByteArray b(ack_packet->GetData(), ack_packet->GetDataSize());
    //qDebug() << "ack_packet" << b;
    handshake_ack = Packet::CreateControl(sequence_number, ControlType::HandshakeACK, HANDSHAKE_ACK_PAYLOAD_BYTES);
    //QByteArray a(handshake_ack->GetData(), handshake_ack->GetDataSize());
    //qDebug() << "handshake_ack" << a;
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

void Node::HandleControlPacket(Packet * control_packet)
{
    //qDebug() << "NODE HANDLE PACKET";
    switch (control_packet->GetControlType()) {
        case ControlType::ACK: {
        //qDebug() << "RECEIVED CONTROL ACK";
            if (has_received_handshake_ack) {
                // read the ACKed sequence number
                uint32_t ack;
                control_packet->read(reinterpret_cast<char*>(&ack), sizeof(uint32_t));

                if (ack <= last_ack_received) {
                    // this is an out of order ACK, bail
                    // or
                    // processing an already received ACK, bail
                    return;
                }

                last_ack_received = ack;
            }
            break;
        }
        case ControlType::Handshake: {
        //qDebug() << "RECEIVED CONTROL HANDSHAKE";
            uint32_t seq;
            control_packet->read(reinterpret_cast<char*>(&seq), sizeof(uint32_t));

            if (!has_received_handshake || seq != initial_receive_sequence_number) {
                // server sent us a handshake - we need to assume this means state should be reset
                // as long as we haven't received a handshake yet or we have and we've received some data
                initial_receive_sequence_number = seq;
                last_receive_sequence_number = seq - 1;
            }

            handshake_ack->reset();
            handshake_ack->write(reinterpret_cast<const char*>(&seq), sizeof(uint32_t));
            node_socket->writeDatagram(handshake_ack->GetData(), handshake_ack->GetDataSize(), public_address, public_port);

            // indicate that handshake has been received
            has_received_handshake = true;

            if (did_request_handshake) {
                did_request_handshake = false;
            }
            break;
        }
        case ControlType::HandshakeACK: {
        //qDebug() << "RECEIVED CONTROL HANDSHAKE ACK";
            // if we've decided to clean up the send queue then this handshake ACK should be ignored, it's useless
            uint32_t seq;
            control_packet->read(reinterpret_cast<char*>(&seq), sizeof(uint32_t));

            //qDebug() << "handshake ack" << seq << initial_sequence_number;
            if (seq == initial_sequence_number) {
                // indicate that handshake ACK was received
                has_received_handshake_ack = true;
                Q_EMIT HandshakeAckReceived();
            }
            break;
        }
        case ControlType::HandshakeRequest: {
        //qDebug() << "RECEIVED HANDSHAKE REQUEST";
            if (has_received_handshake_ack) {
                // We're already in a state where we've received a handshake ack, so we are likely in a state
                // where the other end expired our connection. Let's reset.
                has_received_handshake_ack = false;
            }
            break;
        }
    }
}

void Node::SendHandshake()
{
    auto handshake_packet = Packet::CreateControl(initial_sequence_number, ControlType::Handshake, sizeof(initial_sequence_number));
    handshake_packet->write(reinterpret_cast<const char*>(&initial_sequence_number), sizeof(initial_sequence_number));
    node_socket->writeDatagram(handshake_packet->GetData(), handshake_packet->GetDataSize(), public_address, public_port);
    //QByteArray b(handshake_packet->GetData(), handshake_packet->GetDataSize());
    //qDebug() << "handshake" << b;
}

void Node::SendHandshakeRequest()
{
    auto handshake_request_packet = Packet::CreateControl(sequence_number, ControlType::HandshakeRequest, 0);
    node_socket->writeDatagram(handshake_request_packet->GetData(), handshake_request_packet->GetDataSize(), public_address, public_port);
    //QByteArray b(handshake_request_packet->GetData(), handshake_request_packet->GetDataSize());
    //qDebug() << "handshake" << b;
    did_request_handshake = true;
}
