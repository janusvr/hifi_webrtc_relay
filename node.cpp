#include "node.h"

Node::Node()
{
    authenticate_hash = nullptr;
    num_requests = 0;
    started_negotiating_audio_format = false;
    negotiated_audio_format = false;

    sequence_number = 0;

    restart_ping_timer = new QTimer { this };
    restart_ping_timer->setInterval(1000); // 250ms, Qt::CoarseTimer acceptable
    connect(restart_ping_timer, &QTimer::timeout, this, &Node::StartPing);
    restart_ping_timer->setSingleShot(true);

    ping_timer = new QTimer { this };
    connect(ping_timer, &QTimer::timeout, this, &Node::SendPing);
    ping_timer->setInterval(HIFI_PING_UPDATE_INTERVAL_MSEC); // 250ms, Qt::CoarseTimer acceptable
}

Node::~Node()
{
    if (ping_timer)
    {
        delete ping_timer;
        ping_timer = NULL;
    }
    if (restart_ping_timer)
    {
        delete restart_ping_timer;
        restart_ping_timer = NULL;
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

    StartPing();
}

void Node::StartPing()
{
    // start the ping timer for this node
    num_ping_requests = 0;
    ping_timer->start();
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
    if (num_ping_requests == 500 / HIFI_PING_UPDATE_INTERVAL_MSEC)
    {
        if (num_ping_requests > 500 / HIFI_PING_UPDATE_INTERVAL_MSEC) return;
        //qDebug() << "Node::SendPing() - Restarting ping requests to" << (char) GetNodeType();

        ping_timer->stop();
        ++num_ping_requests;
        restart_ping_timer->start();
        return;
    }
    else
    {
        ++num_ping_requests;
    }

    Ping(1);
    Ping(2);
}

void Node::Ping(quint8 ping_type)
{
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
}
void Node::PingReply(Packet * packet)
{
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

    //qDebug() << "Node::RelayToClient() - Ping reply to node: " << (char) node_type << response_packet->GetSequenceNumber() << type_from_original_ping << time_from_original_ping << time_now << sender << sender_port;
    node_socket->writeDatagram(reply_packet->GetData(), reply_packet->GetDataSize(), public_address, public_port);
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
