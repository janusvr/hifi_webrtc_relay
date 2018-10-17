#include <random>

#include "node.h"

Node::Node()
{
    authenticate_hash = nullptr;
    num_requests = 0;
    started_negotiating_audio_format = false;
    negotiated_audio_format = false;

    static std::random_device rd;
    static std::mt19937 generator(rd());
    static std::uniform_int_distribution<> distribution(0, 0x07FFFFFF);
    sequence_number = distribution(generator);

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

void Node::SetNegotiatedAudioFormat(bool b)
{
    negotiated_audio_format = b;
}

void Node::StartNegotiateAudioFormat()
{
    if (!negotiated_audio_format && !started_negotiating_audio_format && node_type == NodeType::AudioMixer) {
        // start the ping timer for this node
        started_negotiating_audio_format = true;
        num_requests = 0;

        hifi_response_timer = new QTimer { this };
        connect(hifi_response_timer, &QTimer::timeout, this, &Node::SendNegotiateAudioFormat);
        hifi_response_timer->setInterval(HIFI_INITIAL_UPDATE_INTERVAL_MSEC); // 250ms, Qt::CoarseTimer acceptable
        hifi_response_timer->start();
    }
}

void Node::SendPing()
{
    //Ping(1);
    Ping(2);
}

void Node::Ping(quint8 ping_type)
{
    if (!has_received_handshake_ack) {
        SendHandshakeRequest();
        return;
    }

    quint64 timestamp = Utils::GetTimestamp(); // in usec
    int64_t connection_id = 0;

    int packet_size = sizeof(quint8) + sizeof(quint64) + sizeof(int64_t);

    std::unique_ptr<Packet> ping_packet = Packet::Create(sequence_number, PacketType::Ping, packet_size);

    ping_packet->write(reinterpret_cast<const char*>(&ping_type), sizeof(ping_type));
    ping_packet->write(reinterpret_cast<const char*>(&timestamp), sizeof(timestamp));
    ping_packet->write(reinterpret_cast<const char*>(&connection_id), sizeof(connection_id));

    ping_packet->WriteSourceID(domain_session_local_id);
    ping_packet->WriteVerificationHash(authenticate_hash.get());

    //qDebug() << "Node::SendPing() - Pinging to node: " << (char) node_type << ping_type << timestamp << connection_id << node_socket->peerAddress() << node_socket->peerPort() << ping_packet->GetDataSize();
    node_socket->writeDatagram(ping_packet->GetData(), ping_packet->GetDataSize(), (ping_type == 1)?local_address:public_address, (ping_type == 1)?local_port:public_port);
    sequence_number++;
}
void Node::PingReply(Packet * packet, QHostAddress sender, quint16 sender_port)
{
    if (!has_received_handshake_ack) {
        SendHandshakeRequest();
        return;
    }

    const char * message = packet->readAll().constData();

    quint8 type_from_original_ping;
    quint64 time_from_original_ping;
    quint64 time_now = Utils::GetTimestamp();
    memcpy(&type_from_original_ping, message, sizeof(quint8));
    memcpy(&time_from_original_ping, message + sizeof(type_from_original_ping), sizeof(quint64));
    //qDebug() << type_from_original_ping << time_from_original_ping << time_now;

    int packet_size = sizeof(quint8) + sizeof(quint64) + sizeof(quint64);
    auto reply_packet = Packet::Create(sequence_number, PacketType::PingReply, packet_size);
    reply_packet->write(reinterpret_cast<const char*>(&type_from_original_ping), sizeof(type_from_original_ping));
    reply_packet->write(reinterpret_cast<const char*>(&time_from_original_ping), sizeof(time_from_original_ping));
    reply_packet->write(reinterpret_cast<const char*>(&time_now), sizeof(time_now));

    reply_packet->WriteSourceID(domain_session_local_id);
    reply_packet->WriteVerificationHash(authenticate_hash.get());

    //qDebug() << "Node::RelayToClient() - Ping reply to node: " << (char) node_type << type_from_original_ping << time_from_original_ping << time_now << sender << sender_port;
    node_socket->writeDatagram(reply_packet->GetData(), reply_packet->GetDataSize(), sender, sender_port);
    sequence_number++;
}

void Node::SendNegotiateAudioFormat()
{
    if (num_requests == HIFI_NUM_INITIAL_REQUESTS_BEFORE_FAIL)
    {
        qDebug() << "Node::SendNegotiateAudioFormat() - Stopping negotiations of audio format";
        hifi_response_timer->stop();
        hifi_response_timer->deleteLater();
        return;
    }

    if (!negotiated_audio_format) {
        qDebug() << "Node::SendNegotiateAudioFormat() - Negotiating";
        ++num_requests;
    }
    else {
        qDebug() << "Node::SendNegotiateAudioFormat() - Completed negotiations";
        hifi_response_timer->stop();
        hifi_response_timer->deleteLater();
        return;
    }

    auto negotiate_format_packet = Packet::Create(0,PacketType::NegotiateAudioFormat);
    quint8 number_of_codecs = 2; //2 - pcm and zlib
    negotiate_format_packet->write(reinterpret_cast<const char*>(&number_of_codecs), sizeof(number_of_codecs));
    negotiate_format_packet->WriteString(QString("pcm"));
    negotiate_format_packet->WriteString(QString("zlib"));

    negotiate_format_packet->WriteSourceID(domain_session_local_id);
    negotiate_format_packet->WriteVerificationHash(authenticate_hash.get());

    node_socket->writeDatagram(negotiate_format_packet->GetData(), negotiate_format_packet->GetDataSize(), public_address, public_port);
    sequence_number++;
}

void Node::SetDataChannel(std::shared_ptr<rtcdcpp::DataChannel> channel)
{
    if (channel == nullptr) {
        data_channel = channel;
        return;
    }

    std::function<void(std::string)> onStringMessageCallback = [this](std::string message) {
        QString m = QString::fromStdString(message);
        qDebug() << "Node::onMessage() - " << (char) this->GetNodeType() << m;
        this->SendMessageToServer(m);
    };
    channel->SetOnStringMsgCallback(onStringMessageCallback);

    std::function<void(rtcdcpp::ChunkPtr)> onBinaryMessageCallback = [this](rtcdcpp::ChunkPtr message) {
        QByteArray m = QByteArray((char *) message->Data(), message->Length());
        qDebug() << "Node::onMessage() - " << (char) this->GetNodeType() << m;
        this->SendMessageToServer(m);
    };
    channel->SetOnBinaryMsgCallback(onBinaryMessageCallback);

    std::function<void()> onClosed = [this]() {
        qDebug() << "Node::onClosed() - Data channel closed" << (char) node_type;
        this->SetDataChannel(nullptr);
        Q_EMIT Disconnected();
    };
    channel->SetOnClosedCallback(onClosed);

    data_channel = channel;
    //SendMessageToClient(QString("node_message"));
}

bool Node::CheckNodeAddress(QHostAddress a, quint16 p)
{
    //qDebug() << a.toIPv4Address()<< public_address.toIPv4Address() << p << public_port;
    return (a.toIPv4Address() == public_address.toIPv4Address() && p == public_port);
}

void Node::HandleControlPacket(Packet * control_packet)
{
    qDebug() << "NODE HANDLE PACKET";
    switch (control_packet->GetControlType()) {
        case ControlType::ACK: {
        qDebug() << "RECEIVED CONTROL ACK";
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
        qDebug() << "RECEIVED CONTROL HANDSHAKE";
            uint32_t initial_sequence_number;
            control_packet->read(reinterpret_cast<char*>(&initial_sequence_number), sizeof(uint32_t));

            if (!has_received_handshake || initial_sequence_number != sequence_number) {
                // server sent us a handshake - we need to assume this means state should be reset
                // as long as we haven't received a handshake yet or we have and we've received some data
                sequence_number = initial_sequence_number;
                last_sequence_number = initial_sequence_number - 1;
            }

            handshake_ack->reset();
            handshake_ack->write(reinterpret_cast<const char*>(&initial_sequence_number), sizeof(uint32_t));
            node_socket->writeDatagram(handshake_ack->GetData(), handshake_ack->GetDataSize(), public_address, public_port);

            // indicate that handshake has been received
            has_received_handshake = true;

            if (did_request_handshake) {
                did_request_handshake = false;
            }
            break;
        }
        case ControlType::HandshakeACK: {
        qDebug() << "RECEIVED CONTROL HANDSHAKE ACK";
            // if we've decided to clean up the send queue then this handshake ACK should be ignored, it's useless
            uint32_t initial_sequence_number;
            control_packet->read(reinterpret_cast<char*>(&initial_sequence_number), sizeof(uint32_t));

            qDebug() << "handshake ack" << initial_sequence_number << sequence_number;
            if (initial_sequence_number == sequence_number) {
                // indicate that handshake ACK was received
                has_received_handshake_ack = true;
            }
            break;
        }
        case ControlType::HandshakeRequest: {
        qDebug() << "RECEIVED HANDSHAKE REQUEST";
            if (has_received_handshake_ack) {
                // We're already in a state where we've received a handshake ack, so we are likely in a state
                // where the other end expired our connection. Let's reset.
                has_received_handshake_ack = false;
            }
            break;
        }
    }
}

void Node::SendHandshakeRequest()
{
    auto handshake_request_packet = Packet::CreateControl(sequence_number, ControlType::HandshakeRequest, 0);
    node_socket->writeDatagram(handshake_request_packet->GetData(), handshake_request_packet->GetDataSize(), public_address, public_port);
    //QByteArray b(handshake_request_packet->GetData(), handshake_request_packet->GetDataSize());
    //qDebug() << "handshake" << b;
    did_request_handshake = true;
}
