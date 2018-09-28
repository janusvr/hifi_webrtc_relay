#include "node.h"

Node::Node()
{
    connected = false;
    authenticate_hash = nullptr;
    //num_requests = 0;
    //started_negotiating_audio_format = false;
    //negotiated_audio_format = false;
}

Node::~Node()
{

}

void Node::setNodeID(QUuid n)
{
    node_id = n;
}

void Node::setNodeType(NodeType_t n)
{
    node_type = n;
}

void Node::setPublicAddress(QHostAddress a, quint16 p)
{
    public_address = a;
    public_port = p;
}

void Node::setLocalAddress(QHostAddress a, quint16 p)
{
    local_address = a;
    local_port = p;
}

void Node::setSessionLocalID(quint16 s)
{
    session_local_id = s;
}

void Node::setDomainSessionLocalID(quint16 s)
{
    domain_session_local_id = s;
}

void Node::setIsReplicated(bool b)
{
    is_replicated = b;
}

void Node::setConnectionSecret(QUuid c)
{
    if (connection_secret == c) {
        return;
    }

    if (!authenticate_hash) {
        authenticate_hash.reset(new HMACAuth());
    }

    connection_secret = c;
    authenticate_hash->setKey(c);
}

void Node::setPermissions(Permissions p)
{
    permissions = p;
}

void Node::activatePublicSocket(QHostAddress l, quint16 p)
{
    node_socket = new QUdpSocket(this);
    node_socket->bind(l,p,QAbstractSocket::ShareAddress);
    node_socket->connectToHost(public_address, public_port, QIODevice::ReadWrite);
    node_socket->waitForConnected();

    connect(node_socket, SIGNAL(readyRead()), this, SLOT(relayToClient()));

    //startPing();
}

/*void Node::startPing()
{
    // start the ping timer for this node
    ping_timer = new QTimer { this };
    connect(ping_timer, &QTimer::timeout, this, &Node::sendPing);
    ping_timer->setInterval(HIFI_PING_UPDATE_INTERVAL_MSEC); // 250ms, Qt::CoarseTimer acceptable
    ping_timer->start();
}

void Node::startNegotiateAudioFormat()
{
    // start the ping timer for this node
    started_negotiating_audio_format = true;
    num_requests = 0;

    hifi_response_timer = new QTimer { this };
    connect(hifi_response_timer, &QTimer::timeout, this, &Node::sendNegotiateAudioFormat);
    hifi_response_timer->setInterval(HIFI_INITIAL_UPDATE_INTERVAL_MSEC); // 250ms, Qt::CoarseTimer acceptable
    hifi_response_timer->start();
}

void Node::sendPing()
{
    if (connected)
    {
        qDebug() << "Node::sendPing() - Stopping pings to node: " << (char) node_type;
        ping_timer->stop();
        ping_timer->deleteLater();

        return;
    }

    quint8 pingType = 2;
    quint64 timestamp = Utils::GetTimestamp(); // in usec
    int64_t connection_id = 0;

    int packetSize = sizeof(quint8) + sizeof(quint64) + sizeof(int64_t);

    std::unique_ptr<Packet> pingPacket = Packet::create(0, PacketType::Ping, packetSize);

    pingPacket->write(reinterpret_cast<const char*>(&pingType), sizeof(pingType));
    pingPacket->write(reinterpret_cast<const char*>(&timestamp), sizeof(timestamp));
    pingPacket->write(reinterpret_cast<const char*>(&connection_id), sizeof(connection_id));

    pingPacket->writeSourceID(domain_session_local_id);
    pingPacket->writeVerificationHash(authenticate_hash.get());

    //qDebug() << "Node::sendPing() - Pinging to node: " << (char) node_type << pingType << timestamp << connection_id << node_socket->peerAddress() << node_socket->peerPort() << pingPacket->getDataSize();
    node_socket->write(pingPacket->getData(), pingPacket->getDataSize());
}

void Node::sendNegotiateAudioFormat()
{
    if (num_requests == HIFI_NUM_INITIAL_REQUESTS_BEFORE_FAIL)
    {
        qDebug() << "Node::sendNegotiateAudioFormat() - Stopping negotiations of audio format";
        hifi_response_timer->stop();
        hifi_response_timer->deleteLater();
        return;
    }

    if (!negotiated_audio_format) {
        qDebug() << "Node::sendNegotiateAudioFormat() - Negotiating";
        ++num_requests;
    }
    else {
        qDebug() << "Node::sendNegotiateAudioFormat() - Completed negotiations";
        hifi_response_timer->stop();
        hifi_response_timer->deleteLater();
        return;
    }

    auto negotiateFormatPacket = Packet::create(0,PacketType::NegotiateAudioFormat);
    quint8 numberOfCodecs = 2; //2 - pcm and zlib
    negotiateFormatPacket->write(reinterpret_cast<const char*>(&numberOfCodecs), sizeof(numberOfCodecs));
    negotiateFormatPacket->writeString(QString("pcm"));
    negotiateFormatPacket->writeString(QString("zlib"));

    negotiateFormatPacket->writeSourceID(domain_session_local_id);
    negotiateFormatPacket->writeVerificationHash(authenticate_hash.get());

    node_socket->write(negotiateFormatPacket->getData(), negotiateFormatPacket->getDataSize());
}*/

QUdpSocket * Node::getSocket()
{
    return node_socket;
}

void Node::relayToClient()
{
    while (node_socket->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(node_socket->pendingDatagramSize());
        QHostAddress sender;
        quint16 senderPort;

        node_socket->readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);
        /*std::unique_ptr<Packet> responsePacket = Packet::fromReceivedPacket(datagram.data(), (qint64) datagram.size(), sender, senderPort);
        //qDebug() << "Node::relayToClient() - " << (char) node_type << (int) responsePacket->getType() << sender << senderPort;
        if (responsePacket->getType() == PacketType::Ping) {
            //qDebug() << "Node::relayToClient() - Send ping reply";

            const char * message = responsePacket->readAll().constData();

            quint8 typeFromOriginalPing;
            quint64 timeFromOriginalPing;
            quint64 timeNow = Utils::GetTimestamp();
            memcpy(&typeFromOriginalPing, message, sizeof(quint8));
            memcpy(&timeFromOriginalPing, message + sizeof(typeFromOriginalPing), sizeof(quint64));
            //qDebug() << typeFromOriginalPing << timeFromOriginalPing << timeNow;

            int packetSize = sizeof(quint8) + sizeof(quint64) + sizeof(quint64);
            auto replyPacket = Packet::create(responsePacket->getSequenceNumber(), PacketType::PingReply, packetSize);
            replyPacket->write(reinterpret_cast<const char*>(&typeFromOriginalPing), sizeof(typeFromOriginalPing));
            replyPacket->write(reinterpret_cast<const char*>(&timeFromOriginalPing), sizeof(timeFromOriginalPing));
            replyPacket->write(reinterpret_cast<const char*>(&timeNow), sizeof(timeNow));

            replyPacket->writeSourceID(domain_session_local_id);
            replyPacket->writeVerificationHash(authenticate_hash.get());

            //qDebug() << "Node::relayToClient() - Ping reply to node: " << (char) node_type << responsePacket->getSequenceNumber() << typeFromOriginalPing << timeFromOriginalPing << timeNow << sender << senderPort;
            node_socket->write(replyPacket->getData(), replyPacket->getDataSize());
        }
        else if (responsePacket->getType() == PacketType::SelectedAudioFormat) {
            negotiated_audio_format = true;
            qDebug() << "Node::relayToClient() - Negotiated audio format" << responsePacket->readString();
        }
        else if (responsePacket->getType() == PacketType::PingReply) {
            connected = true;
            //qDebug() << "Node::relayToClient() - " << (char) node_type << (int) responsePacket->getType() << sender << senderPort;

            if (!negotiated_audio_format && !started_negotiating_audio_format && node_type == NodeType::AudioMixer) {
                startNegotiateAudioFormat();
            }
        }
        else if (connected){*/
            qDebug() << "Node::relayToClient() - Relay to client";
            SendMessageToClient(datagram);
        //}
    }
}

void Node::setDataChannel(std::shared_ptr<rtcdcpp::DataChannel> channel)
{
    if (channel == nullptr) {
        data_channel = channel;
        return;
    }

    std::function<void(std::string)> onStringMessageCallback = [this](std::string message) {
        QString m = QString::fromStdString(message);
        qDebug() << "Node::onMessage() - " << (char) this->getNodeType() << m;
        this->SendMessageToServer(m);
    };
    channel->SetOnStringMsgCallback(onStringMessageCallback);

    std::function<void(rtcdcpp::ChunkPtr)> onBinaryMessageCallback = [this](rtcdcpp::ChunkPtr message) {
        QByteArray m = QByteArray((char *) message->Data(), message->Length());
        qDebug() << "Node::onMessage() - " << (char) this->getNodeType() << m;
        this->SendMessageToServer(m);
    };
    channel->SetOnBinaryMsgCallback(onBinaryMessageCallback);

    std::function<void()> onClosed = [this]() {
        qDebug() << "Node::onClosed() - Data channel closed" << (char) node_type;
        this->setDataChannel(nullptr);
    };
    channel->SetOnClosedCallback(onClosed);

    data_channel = channel;
    SendMessageToClient(QString("node_message")); // TODO: remove this test message
}
