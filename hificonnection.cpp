#include <random>

#include "hificonnection.h"

HifiConnection::HifiConnection(QWebSocket * s)
{
    domain_name = "";
    domain_place_name = "";
    domain_id = QUuid();
    finished_domain_id_request = false;
    stun_server_hostname = "stun.highfidelity.io";
    stun_server_address = QHostAddress();
    stun_server_port = 3478;
    ice_server_hostname = "ice.highfidelity.com"; //"dev-ice.highfidelity.com";

    pinged = false;
    pingreplied = false;

    has_received_handshake_ack = false;
    did_request_handshake = false;

    static std::random_device rd;
    static std::mt19937 generator(rd());
    static std::uniform_int_distribution<> distribution(0, 0x07FFFFFF);
    sequence_number = distribution(generator);

    static const int ACK_PACKET_PAYLOAD_BYTES = sizeof(uint32_t);
    static const int HANDSHAKE_ACK_PAYLOAD_BYTES = sizeof(uint32_t);
    ack_packet = Packet::CreateControl(sequence_number, ControlType::ACK, ACK_PACKET_PAYLOAD_BYTES);
    QByteArray b(ack_packet->GetData(), ack_packet->GetDataSize());
    qDebug() << "ack_packet" << b;
    handshake_ack = Packet::CreateControl(sequence_number, ControlType::HandshakeACK, HANDSHAKE_ACK_PAYLOAD_BYTES);
    QByteArray a(handshake_ack->GetData(), handshake_ack->GetDataSize());
    qDebug() << "handshake_ack" << a;

    qDebug() << "HifiConnection::HifiConnection() - Synchronously looking up IP address for hostname" << stun_server_hostname;
    QHostInfo result_stun = QHostInfo::fromName(stun_server_hostname);
    HandleLookupResult(result_stun, "stun");
    //qDebug() << "HifiConnection::HifiConnection() - STUN server IP address: " << stun_server_hostname;

    qDebug() << "HifiConnection::HifiConnection() - Synchronously looking up IP address for hostname" << ice_server_hostname;
    QHostInfo result_ice = QHostInfo::fromName(ice_server_hostname);
    HandleLookupResult(result_ice, "ice");
    //qDebug() << "HifiConnection::HifiConnection() - ICE server IP address: " << ice_server_hostname;

    ice_server_address = Utils::GetDefaultIceServerAddress();
    ice_server_port = Utils::GetDefaultIceServerPort();

    has_tcp_checked_local_socket = false;
    UpdateLocalSocket();

    connect(this, SIGNAL(WebRTCConnectionReady()), this, SLOT(HifiConnect()));
    connect(this, SIGNAL(StartHifiConnection()), this, SLOT(StartStun()));
    connect(this, SIGNAL(StunFinished()), this, SLOT(StartIce()));
    connect(this, SIGNAL(IceFinished()), this, SLOT(StartDomainIcePing()));
    connect(this, SIGNAL(DomainIcePingFinished()), this, SLOT(StartDomainConnect()));

    connect(this, SIGNAL(DomainServerHasReceivedHandshakeAck()), this, SLOT(ParsePendingDatagrams()));

    ice_client_id = QUuid::createUuid();

    started_domain_connect = false;

    owner_type = NodeType::Agent;
    node_types_of_interest = NodeSet() << NodeType::AudioMixer << NodeType::AvatarMixer << NodeType::EntityServer << NodeType::AssetServer << NodeType::MessagesMixer << NodeType::EntityScriptServer;

    domain_connected = false;

    asset_server = nullptr;
    audio_mixer = nullptr;
    avatar_mixer = nullptr;
    messages_mixer = nullptr;
    entity_server = nullptr;
    entity_script_server = nullptr;
    domain_server_dc = nullptr;
    audio_mixer_dc = nullptr;
    avatar_mixer_dc = nullptr;
    messages_mixer_dc = nullptr;
    asset_server_dc = nullptr;
    entity_server_dc = nullptr;
    entity_script_server_dc = nullptr;

    hifi_ping_timer = new QTimer { this };
    connect(hifi_ping_timer, &QTimer::timeout, this, &HifiConnection::SendDomainIcePing);
    hifi_ping_timer->setInterval(HIFI_PING_UPDATE_INTERVAL_MSEC); // 250ms, Qt::CoarseTimer acceptable

    stun_response_timer = new QTimer { this };
    connect(stun_response_timer, &QTimer::timeout, this, &HifiConnection::SendStunRequest);
    stun_response_timer->setInterval(HIFI_INITIAL_UPDATE_INTERVAL_MSEC); // 250ms, Qt::CoarseTimer acceptable

    ice_response_timer = new QTimer { this };
    connect(ice_response_timer, &QTimer::timeout, this, &HifiConnection::SendIceRequest);
    ice_response_timer->setInterval(HIFI_INITIAL_UPDATE_INTERVAL_MSEC); // 250ms, Qt::CoarseTimer acceptable

    hifi_response_timer = new QTimer { this };
    connect(hifi_response_timer, &QTimer::timeout, this, &HifiConnection::SendDomainConnectRequest);
    hifi_response_timer->setInterval(HIFI_INITIAL_UPDATE_INTERVAL_MSEC); // 250ms, Qt::CoarseTimer acceptable

    qDebug() << "HifiConnection::Connect() - New client" << s << ice_client_id << s->peerAddress() << s->peerPort();
    client_socket = s;

    connect(client_socket, &QWebSocket::textMessageReceived, this, &HifiConnection::ClientMessageReceived);
    connect(client_socket, &QWebSocket::disconnected, this, &HifiConnection::ClientDisconnected);

    QJsonObject connected_object;
    connected_object.insert("type", QJsonValue::fromVariant("connected"));
    connected_object.insert("id", QJsonValue::fromVariant(ice_client_id.toString()));
    QJsonDocument connectedDoc(connected_object);
    client_socket->sendTextMessage(QString::fromStdString(connectedDoc.toJson().toStdString()));
}

HifiConnection::~HifiConnection()
{

}

void HifiConnection::HandleLookupResult(const QHostInfo& hostInfo, QString addr_type)
{
    if (hostInfo.error() != QHostInfo::NoError) {
        qDebug() << "Task::handleLookupResult() - Lookup failed for" << hostInfo.lookupId() << ":" << hostInfo.errorString();
    } else {
        for (int i = 0; i < hostInfo.addresses().size(); i++) {
            // just take the first IPv4 address
            QHostAddress address = hostInfo.addresses()[i];
            if (address.protocol() == QAbstractSocket::IPv4Protocol) {

                if (addr_type == "stun") stun_server_address = address;
                else if (addr_type == "ice") ice_server_address = address;

                qDebug() << "Task::handleLookupResult() - QHostInfo lookup result for"
                    << hostInfo.hostName() << "with lookup ID" << hostInfo.lookupId() << "is" << address.toString();
                break;
            }
        }
    }
}

void HifiConnection::UpdateLocalSocket()
{
    // attempt to use Google's DNS to confirm that local IP
    static const QHostAddress RELIABLE_LOCAL_IP_CHECK_HOST = QHostAddress { "8.8.8.8" };
    static const int RELIABLE_LOCAL_IP_CHECK_PORT = 53;

    QTcpSocket* localIPTestSocket = new QTcpSocket;

    connect(localIPTestSocket, &QTcpSocket::connected, this, &HifiConnection::ConnectedForLocalSocketTest);
    connect(localIPTestSocket, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(ErrorTestingLocalSocket()));

    // attempt to connect to our reliable host
    localIPTestSocket->connectToHost(RELIABLE_LOCAL_IP_CHECK_HOST, RELIABLE_LOCAL_IP_CHECK_PORT);
}

void HifiConnection::ConnectedForLocalSocketTest()
{
    auto local_ip_test_socket = qobject_cast<QTcpSocket*>(sender());

    if (local_ip_test_socket) {
        auto local_host_address = local_ip_test_socket->localAddress();

        if (local_host_address.protocol() == QAbstractSocket::IPv4Protocol) {
            local_address = local_host_address;

            //qDebug() << "HifiConnection::connectedForLocalSocketTest() - Local address: " << local_address;

            has_tcp_checked_local_socket = true;
        }

        local_ip_test_socket->deleteLater();
    }
}

void HifiConnection::ErrorTestingLocalSocket()
{
    auto local_ip_test_socket = qobject_cast<QTcpSocket*>(sender());

    if (local_ip_test_socket) {

        // error connecting to the test socket - if we've never set our local socket using this test socket
        // then use our possibly updated guessed local address as fallback
        if (!has_tcp_checked_local_socket) {
            local_address = GetGuessedLocalAddress();

            //qDebug() << "HifiConnection::errorTestingLocalSocket() - Local address: " << local_address;

            has_tcp_checked_local_socket = true;
        }

        local_ip_test_socket->deleteLater();
    }
}


QHostAddress HifiConnection::GetGuessedLocalAddress()
{
    QHostAddress address;

    for (int i= 0; i < QNetworkInterface::allInterfaces().size(); i++) {
        QNetworkInterface network_interface = QNetworkInterface::allInterfaces()[i];
        if (network_interface.flags() & QNetworkInterface::IsUp
            && network_interface.flags() & QNetworkInterface::IsRunning
            && network_interface.flags() & ~QNetworkInterface::IsLoopBack) {
            // we've decided that this is the active NIC
            // enumerate it's addresses to grab the IPv4 address
            for (int j = 0; network_interface.addressEntries().size(); j++) {
                // make sure it's an IPv4 address that isn't the loopback
                QNetworkAddressEntry entry = network_interface.addressEntries()[j];
                if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol && !entry.ip().isLoopback()) {

                    // set our localAddress and break out
                    address = entry.ip();
                    //qDebug() << "HifiConnection::getGuessedLocalAddress() - " << address;
                    break;
                }
            }
        }

        if (!address.isNull()) {
            break;
        }
    }

    has_tcp_checked_local_socket = true;

    // return the looked up local address
    return address;
}

void HifiConnection::Stop()
{
    if (asset_server) delete asset_server;
    if (audio_mixer) delete audio_mixer;
    if (messages_mixer) delete messages_mixer;
    if (avatar_mixer) delete avatar_mixer;
    if (entity_script_server) delete entity_script_server;
    if (entity_server) delete entity_server;

    if (hifi_ping_timer)
    {
        delete hifi_ping_timer;
        hifi_ping_timer = NULL;
    }

    if (ice_response_timer)
    {
        delete ice_response_timer;
        ice_response_timer = NULL;
    }

    if (stun_response_timer)
    {
        delete stun_response_timer;
        stun_response_timer = NULL;
    }

    if (hifi_response_timer)
    {
        delete hifi_response_timer;
        hifi_response_timer = NULL;
    }

    if (client_socket) {
        delete client_socket;
        client_socket = NULL;
    }

    if (hifi_socket) {
        hifi_socket.clear();
    }
}

void HifiConnection::DomainRequestFinished()
{
    if (domain_reply) {
        if (domain_reply->error() == QNetworkReply::NoError && domain_reply->isOpen()) {
            domain_reply_contents += domain_reply->readAll();

            //qDebug() << domain_reply_contents;

            QJsonDocument doc;
            doc = QJsonDocument::fromJson(domain_reply_contents);
            QJsonObject obj = doc.object();
            QJsonObject data = obj["data"].toObject();
            QJsonObject place = data["place"].toObject();
            QJsonObject domain = place["domain"].toObject();
            domain_id = QUuid(domain["id"].toString());
            domain_place_name = domain["default_place_name"].toString();

            if (domain.contains("ice_server_address")) {
                ice_server_address = QHostAddress(domain["ice_server_address"].toString());
            }
        }
        domain_reply->close();
    }

    qDebug() << "HifiConnection::domainRequestFinished() - Domain name" << domain_name;
    qDebug() << "HifiConnection::domainRequestFinished() - Domain place name" << domain_place_name;
    qDebug() << "HifiConnection::domainRequestFinished() - Domain ID" << domain_id;

    finished_domain_id_request = true;
    if (DataChannelsReady() && finished_domain_id_request) {
        Q_EMIT WebRTCConnectionReady();
    }
}

void HifiConnection::HifiConnect()
{
    // Register Domain Server DC callbacks here
    std::function<void(std::string)> onStringMessageCallback = [this](std::string message) {
        QString m = QString::fromStdString(message);
        qDebug() << "HifiConnection::onMessage() - Domain Server" << m;
        this->SendDomainServerMessage(m);
    };
    domain_server_dc->SetOnStringMsgCallback(onStringMessageCallback);

    std::function<void(rtcdcpp::ChunkPtr)> onBinaryMessageCallback = [this](rtcdcpp::ChunkPtr message) {
        QByteArray m = QByteArray((char *) message->Data(), message->Length());
        qDebug() << "HifiConnection::onMessage() - Domain Server" << m;
        this->SendDomainServerMessage(m);
    };
    domain_server_dc->SetOnBinaryMsgCallback(onBinaryMessageCallback);

    std::function<void()> onClosed = [this]() {
        qDebug() << "HifiConnection::onClosed() - Domain Server data channel closed";
        this->SetDomainServerDC(nullptr);
        Q_EMIT Disconnected();
    };
    domain_server_dc->SetOnClosedCallback(onClosed);
    //this->SendDomainServerDCMessage(QString("test_message"));

    hifi_socket = QSharedPointer<QUdpSocket>(new QUdpSocket(this));
    connect(hifi_socket.data(), SIGNAL(readyRead()), this, SLOT(ParseHifiResponse()));

    Q_EMIT StartHifiConnection();
}

void HifiConnection::StartStun()
{
    num_requests = 0;
    has_completed_current_request = false;


    stun_response_timer->start();
}

void HifiConnection::StartIce()
{
    num_requests = 0;
    has_completed_current_request = false;

    ice_response_timer->start();
}

void HifiConnection::StartDomainIcePing()
{
    hifi_ping_timer->start();
}

void HifiConnection::StartDomainConnect()
{
    connect(hifi_socket.data(), SIGNAL(disconnected()), this, SLOT(ServerDisconnected()));

    num_requests = 0;
    has_completed_current_request = false;

    hifi_response_timer->start();
}
void HifiConnection::ParseHifiResponse()
{
    while (hifi_socket->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(hifi_socket->pendingDatagramSize());
        QHostAddress sender;
        quint16 sender_port;

        hifi_socket->readDatagram(datagram.data(), datagram.size(), &sender, &sender_port);

        //Stun Server response;
        if (sender.toIPv4Address() == stun_server_address.toIPv4Address() && sender_port == stun_server_port) {
            //qDebug() << "HifiConnection::ParseHifiResponse() - read packet from " << sender << ":" << sender_port << " of size " << datagram.size() << " bytes";

            // check the cookie to make sure this is actually a STUN response
            // and read the first attribute and make sure it is a XOR_MAPPED_ADDRESS
            const int NUM_BYTES_MESSAGE_TYPE_AND_LENGTH = 4;
            const uint16_t XOR_MAPPED_ADDRESS_TYPE = htons(0x0020);

            const uint32_t RFC_5389_MAGIC_COOKIE_NETWORK_ORDER = htonl(RFC_5389_MAGIC_COOKIE);

            int attribute_start_index = NUM_BYTES_STUN_HEADER;
            if (memcmp(datagram.data() + NUM_BYTES_MESSAGE_TYPE_AND_LENGTH,
                       &RFC_5389_MAGIC_COOKIE_NETWORK_ORDER,
                       sizeof(RFC_5389_MAGIC_COOKIE_NETWORK_ORDER)) != 0) {
                qDebug() << "HifiConnection::ParseHifiResponse() - STUN response cannot be parsed, magic cookie is invalid";
                Q_EMIT Disconnected();
                return;
            }

            // enumerate the attributes to find XOR_MAPPED_ADDRESS_TYPE
            while (attribute_start_index < datagram.size()) {
                if (memcmp(datagram.data() + attribute_start_index, &XOR_MAPPED_ADDRESS_TYPE, sizeof(XOR_MAPPED_ADDRESS_TYPE)) == 0) {
                    const int NUM_BYTES_STUN_ATTR_TYPE_AND_LENGTH = 4;
                    const int NUM_BYTES_FAMILY_ALIGN = 1;
                    const uint8_t IPV4_FAMILY_NETWORK_ORDER = htons(0x01) >> 8;

                    int byte_index = attribute_start_index + NUM_BYTES_STUN_ATTR_TYPE_AND_LENGTH + NUM_BYTES_FAMILY_ALIGN;

                    uint8_t address_family = 0;
                    memcpy(&address_family, datagram.data() + byte_index, sizeof(address_family));

                    byte_index += sizeof(address_family);

                    if (address_family == IPV4_FAMILY_NETWORK_ORDER) {
                        // grab the X-Port
                        uint16_t xor_mapped_port = 0;
                        memcpy(&xor_mapped_port, datagram.data() + byte_index, sizeof(xor_mapped_port));

                        public_port = ntohs(xor_mapped_port) ^ (ntohl(RFC_5389_MAGIC_COOKIE_NETWORK_ORDER) >> 16);

                        byte_index += sizeof(xor_mapped_port);

                        // grab the X-Address
                        uint32_t xor_mapped_address = 0;
                        memcpy(&xor_mapped_address, datagram.data() + byte_index, sizeof(xor_mapped_address));

                        uint32_t stun_address = ntohl(xor_mapped_address) ^ ntohl(RFC_5389_MAGIC_COOKIE_NETWORK_ORDER);

                        // QHostAddress newPublicAddress(stun_address);
                        public_address = QHostAddress(stun_address);

                        qDebug() << "HifiConnection::ParseHifiResponse() - Public address: " << public_address;
                        qDebug() << "HifiConnection::ParseHifiResponse() - Public port: " << public_port;

                        local_port = hifi_socket->localPort();

                        qDebug() << "HifiConnection::ParseHifiResponse() - Local address: " << local_address;
                        qDebug() << "HifiConnection::ParseHifiResponse() - Local port: " << local_port;

                        has_completed_current_request = true;
                        stun_response_timer->stop();

                        SendDomainServerDCMessage(datagram);
                        Q_EMIT StunFinished();
                        break;
                    }
                } else {
                    // push forward attribute_start_index by the length of this attribute
                    const int NUM_BYTES_ATTRIBUTE_TYPE = 2;

                    uint16_t attribute_length = 0;
                    memcpy(&attribute_length, datagram.data() + attribute_start_index + NUM_BYTES_ATTRIBUTE_TYPE,
                           sizeof(attribute_length));
                    attribute_length = ntohs(attribute_length);

                    attribute_start_index += NUM_BYTES_MESSAGE_TYPE_AND_LENGTH + attribute_length;
                }
            }
            continue;
        }

        // Check for control packet
        bool is_control_packet = *reinterpret_cast<uint32_t*>(datagram.data()) & CONTROL_BIT_MASK;
        if (is_control_packet) {
            //qDebug() << "RECEIVED CONTROL PACKET";
            // setup a control packet from the data we just read
            std::unique_ptr<Packet> control_packet = Packet::FromReceivedControlPacket(datagram.data(), (qint64) datagram.size(), sender, sender_port);

            Node * node = GetNodeFromAddress(sender, sender_port);
            if (node) {
                node->HandleControlPacket(control_packet.get());
                node->SendMessageToClient(datagram);
            }
            else {
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
                        hifi_socket->writeDatagram(handshake_ack->GetData(), handshake_ack->GetDataSize(), domain_public_address, domain_public_port);

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
                        uint32_t initial_sequence_number;
                        control_packet->read(reinterpret_cast<char*>(&initial_sequence_number), sizeof(uint32_t));

                        qDebug() << "handshake ack" << initial_sequence_number << sequence_number;
                        if (initial_sequence_number == sequence_number) {
                            // indicate that handshake ACK was received
                            has_received_handshake_ack = true;
                            Q_EMIT DomainServerHasReceivedHandshakeAck();
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
                SendDomainServerDCMessage(datagram);
            }
            continue;
        }

        std::unique_ptr<Packet> response_packet = Packet::FromReceivedPacket(datagram.data(), (qint64) datagram.size(), sender, sender_port);// check if this was a control packet or a data packet
        //qDebug() << "HifiConnection::ParseHifiResponse() - Packet type" << (int) response_packet->GetType();

        //ICE response
        if (response_packet->GetType() == PacketType::ICEServerPeerInformation)
        {
            QDataStream ice_response_stream(response_packet.get()->readAll());
            QUuid domain_uuid;
            ice_response_stream >> domain_uuid >> domain_public_address >> domain_public_port >> domain_local_address >> domain_local_port;

            if (domain_uuid != domain_id){
                qDebug() << "HifiConnection::ParseHifiResponse() - Error: Domain ID's do not match " << domain_uuid << domain_id;
                Q_EMIT Disconnected();
            }

            qDebug() << "HifiConnection::ParseHifiResponse() - Domain ID: " << domain_uuid << "Domain Public Address: " << domain_public_address << "Domain Public Port: " << domain_public_port << "Domain Local Address: " << domain_local_address << "Domain Local Port: " << domain_local_port;

            has_completed_current_request = true;
            if (!started_domain_connect)
            {
                ice_response_timer->stop();
                Q_EMIT IceFinished();
            }

            SendDomainServerDCMessage(datagram);
            continue;
        }

        //Domain Server or Node response (add to queue if packet is reliable and we haven't received a handshake)
        if (response_packet->GetIsReliable()) {
            if (sender.toIPv4Address() == domain_public_address.toIPv4Address() && sender_port == domain_public_port && !has_received_handshake_ack) {
                SendHandshakeRequest();
                pending_datagrams.push_back(new PendingDatagram(datagram, sender, sender_port));
                continue;
            }
            else {
                Node * node = GetNodeFromAddress(sender, sender_port);
                if (node && node->GetHasReceivedHandshakeAck()) {
                    node->SendHandshakeRequest();
                    pending_datagrams.push_back(new PendingDatagram(datagram, sender, sender_port));
                    continue;
                }
            }
        }
        ParseDatagram(datagram, sender, sender_port);
    }
}

void HifiConnection::ParsePendingDatagrams()
{
    while (!pending_datagrams.isEmpty())
    {
        PendingDatagram * p = pending_datagrams.front();
        pending_datagrams.pop_front();
        ParseDatagram(p->GetDatagram(), p->GetSender(), p->GetSenderPort());
        delete p;
    }
}

void HifiConnection::ParseDatagram(QByteArray datagram, QHostAddress sender, quint16 sender_port)
{
    std::unique_ptr<Packet> response_packet = Packet::FromReceivedPacket(datagram.data(), (qint64) datagram.size(), sender, sender_port);// check if this was a control packet or a data packet
    if (response_packet->GetType() == PacketType::ICEPing) {
        //qDebug() << "HifiConnection::ParseHifiResponse() - Send ping reply";
        SendIcePingReply(response_packet.get(), sender, sender_port);
        SendDomainServerDCMessage(datagram);

        pingreplied = true;
        if (pingreplied && pinged && !started_domain_connect)
        {
            started_domain_connect = true;
            Q_EMIT DomainIcePingFinished();
        }
    }
    else if (response_packet->GetType() == PacketType::ICEPingReply) {
        //qDebug() << "HifiConnection::ParseHifiResponse() - Process ping reply";
        SendDomainServerDCMessage(datagram);

        pinged = true;
        if (pingreplied && pinged && !started_domain_connect)
        {
            started_domain_connect = true;
            Q_EMIT DomainIcePingFinished();
        }
    }
    else if (response_packet->GetType() == PacketType::DomainList) {
        qDebug() << "HifiConnection::ParseHifiResponse() - Process domain list";
        QDataStream packet_stream(response_packet->readAll());

        // grab the domain's ID from the beginning of the packet
        QUuid domain_uuid;
        packet_stream >> domain_uuid;

        if (domain_connected && domain_id != domain_uuid) {
            // Recieved packet from different domain.
            qDebug() << "HifiConnection::ParseHifiResponse() - Received packet from different domain";
            return;
        }

        quint16 domain_local_id;
        packet_stream >> domain_local_id;

        // pull our owner (ie. session) UUID from the packet, it's always the first thing
        // The short (16 bit) ID comes next.
        packet_stream >> session_id;
        packet_stream >> local_id;

        // if this was the first domain-server list from this domain, we've now connected
        if (!domain_connected) {
            hifi_response_timer->stop();
            domain_connected = true;
        }

        // pull the permissions/right/privileges for this node out of the stream
        uint new_permissions;
        packet_stream >> new_permissions;
        permissions = (Permissions) new_permissions;

        // Is packet authentication enabled?
        bool is_authenticated;
        packet_stream >> is_authenticated; //TODO: handle authentication of packets

        //qDebug() << permissions << is_authenticated;

        //qDebug() << domain_uuid << domain_local_id << session_id << local_id << new_permissions << is_authenticated;

        // pull each node in the packet
        while (packet_stream.device()->pos() < response_packet->GetDataSize() - response_packet->TotalHeaderSize()) {
            ParseNodeFromPacketStream(packet_stream);
        }

        // Relay domain list packet over to client
        SendDomainServerDCMessage(datagram);
    }
    else if (response_packet->GetType() == PacketType::DomainConnectionDenied) {
        uint8_t reasonCode;
        //uint8_t reasonSize;

        response_packet->read((char *) &reasonCode, sizeof(uint8_t));
        /*response_packet->read((char *) &reasonSize, sizeof(uint8_t));

        QByteArray utfReason;
        utfReason.resize(reasonSize);
        response_packet->read(utfReason.data(), reasonSize);

        QString reason = QString::fromUtf8(utfReason.constData(), reasonSize);*/

        qDebug() << "HifiConnection::ParseHifiResponse() - DomainConnectionDenied - Code: " << reasonCode;  //"Reason: "<< reason;

        SendDomainServerDCMessage(datagram);
    }
    else if (response_packet->GetType() == PacketType::Ping) {
        Node * node = GetNodeFromAddress(sender, sender_port);

        if (node){
            node->SendMessageToClient(datagram);
            node->PingReply(response_packet.get(), sender, sender_port);
        }
    }
    else if (response_packet->GetType() == PacketType::SelectedAudioFormat) {
        qDebug() << "Node::RelayToClient() - Negotiated audio format" << response_packet->ReadString();

        if (audio_mixer->CheckNodeAddress(sender, sender_port)) {
            audio_mixer->SetNegotiatedAudioFormat(true);
            audio_mixer->SendMessageToClient(datagram);
        }
    }
    else if (response_packet->GetType() == PacketType::PingReply) {
        Node * node = GetNodeFromAddress(sender, sender_port);

        if (node){
            node->SendMessageToClient(datagram);

            //qDebug() << "Node::RelayToClient() - Ping reply from: " << sender << sender_port;
            if (audio_mixer->CheckNodeAddress(sender, sender_port)) {
                audio_mixer->StartNegotiateAudioFormat();
            }
        }
    }
    else {
        // Send any other types of packets to the client
        Node * node = GetNodeFromAddress(sender, sender_port);

        if (node) {
            node->SendMessageToClient(datagram);
        }
        else {
            SendDomainServerDCMessage(datagram);
        }
    }
}

void HifiConnection::ParseNodeFromPacketStream(QDataStream& packet_stream)
{
    // setup variables to read into from QDataStream
    NodeType_t node_type;
    QUuid node_uuid, connection_secret_uuid;
    QHostAddress node_public_address, node_local_address;
    quint16 node_public_port, node_local_port;
    uint node_permissions;
    bool is_replicated;
    quint16 session_local_id;

    packet_stream >> node_type >> node_uuid >> node_public_address >> node_public_port >> node_local_address >> node_local_port >> node_permissions
        >> is_replicated >> session_local_id >> connection_secret_uuid;

    // if the public socket address is 0 then it's reachable at the same IP
    // as the domain server
    if (node_public_address.isNull()) {
        node_public_address = public_address;
    }

    //qDebug() << (char) node_type << node_uuid << node_public_address << node_public_port << node_local_address << node_local_port << node_permissions
    //          << is_replicated << session_local_id << connection_secret_uuid;

    Node * node = new Node();
    node->SetNodeID(node_uuid);
    node->SetNodeType(node_type);
    node->SetPublicAddress(node_public_address, node_public_port);
    node->SetLocalAddress(node_local_address, node_local_port);
    node->SetSessionLocalID(session_local_id);
    node->SetDomainSessionLocalID(local_id);
    node->SetIsReplicated(is_replicated);
    node->SetConnectionSecret(connection_secret_uuid);
    node->SetPermissions((Permissions) node_permissions);

    // nodes that are downstream or upstream of our own type are kept alive when we hear about them from the domain server
    // and always have their public socket as their active socket
    //if (node->GetType() == NodeType::downstreamType(_ownerType) || node->GetType() == NodeType::upstreamType(_ownerType)) {
    //    node->setLastHeardMicrostamp(usecTimestampNow());
        node->ActivatePublicSocket(hifi_socket);
        //node->sendPing();
    //}

    switch (node_type) {
        case NodeType::AssetServer : {
            qDebug() << "HifiConnection::ParseNodeFromPacketStream() - Registering asset server" << node_public_address << node_public_port;
            asset_server = node;
            asset_server->SetDataChannel(asset_server_dc);
            connect(asset_server, SIGNAL(Disconnected()), this, SLOT(NodeDisconnected()));
            connect(asset_server, SIGNAL(HandshakeAckReceived()), this, SLOT(ParsePendingDatagrams()));
            //asset_server->SendPing();
            break;
        }
        case NodeType::AudioMixer : {
            qDebug() << "HifiConnection::ParseNodeFromPacketStream() - Registering audio mixer" << node_public_address << node_public_port;
            audio_mixer = node;
            audio_mixer->SetDataChannel(audio_mixer_dc);
            connect(audio_mixer, SIGNAL(Disconnected()), this, SLOT(NodeDisconnected()));
            connect(audio_mixer, SIGNAL(HandshakeAckReceived()), this, SLOT(ParsePendingDatagrams()));
            //audio_mixer->SendPing();
            break;
        }
        case NodeType::AvatarMixer : {
            qDebug() << "HifiConnection::ParseNodeFromPacketStream() - Registering avatar mixer" << node_public_address << node_public_port;
            avatar_mixer = node;
            avatar_mixer->SetDataChannel(avatar_mixer_dc);
            connect(avatar_mixer, SIGNAL(Disconnected()), this, SLOT(NodeDisconnected()));
            connect(avatar_mixer, SIGNAL(HandshakeAckReceived()), this, SLOT(ParsePendingDatagrams()));
            //avatar_mixer->SendPing();
            break;
        }
        case NodeType::MessagesMixer : {
            qDebug() << "HifiConnection::ParseNodeFromPacketStream() - Registering messages mixer" << node_public_address << node_public_port;
            messages_mixer = node;
            messages_mixer->SetDataChannel(messages_mixer_dc);
            connect(messages_mixer, SIGNAL(Disconnected()), this, SLOT(NodeDisconnected()));
            connect(messages_mixer, SIGNAL(HandshakeAckReceived()), this, SLOT(ParsePendingDatagrams()));
            //messages_mixer->SendPing();
            break;
        }
        case NodeType::EntityServer : {
            qDebug() << "HifiConnection::ParseNodeFromPacketStream() - Registering entity server" << node_public_address << node_public_port;
            entity_server = node;
            entity_server->SetDataChannel(entity_server_dc);
            connect(entity_server, SIGNAL(Disconnected()), this, SLOT(NodeDisconnected()));
            connect(entity_server, SIGNAL(HandshakeAckReceived()), this, SLOT(ParsePendingDatagrams()));
            //entity_server->SendPing();
            break;
        }
        case NodeType::EntityScriptServer : {
            qDebug() << "HifiConnection::ParseNodeFromPacketStream() - Registering entity script server" << node_public_address << node_public_port;
            entity_script_server = node;
            entity_script_server->SetDataChannel(entity_script_server_dc);
            connect(entity_script_server, SIGNAL(Disconnected()), this, SLOT(NodeDisconnected()));
            connect(asset_server, SIGNAL(HandshakeAckReceived()), this, SLOT(ParsePendingDatagrams()));
            //entity_script_server->SendPing();
            break;
        }
        default: {
            break;
        }
    }
}

void HifiConnection::SendStunRequest()
{
    if (!finished_domain_id_request || !has_tcp_checked_local_socket) {
        return;
    }

    if (num_requests == HIFI_NUM_INITIAL_REQUESTS_BEFORE_FAIL)
    {
        qDebug() << "HifiConnection::SendStunRequest() - Stopping stun requests to" << stun_server_hostname << stun_server_port;
        stun_response_timer->stop();
        Q_EMIT Disconnected();
        //disconnect(stun_response_timer, &QTimer::timeout, this, &HifiConnection::SendStunRequest);
        //stun_response_timer->deleteLater();
        return;
    }

    if (!has_completed_current_request) {
        qDebug() << "HifiConnection::SendStunRequest() - Sending initial stun request to" << stun_server_hostname << stun_server_port;
        ++num_requests;
    }
    else {
        //qDebug() << "HifiConnection::SendStunRequest() - Completed stun request";
        return;
    }

    char * stun_request_packet = (char *) malloc(NUM_BYTES_STUN_HEADER);

    int packet_index = 0;
    const uint32_t RFC_5389_MAGIC_COOKIE_NETWORK_ORDER = htonl(RFC_5389_MAGIC_COOKIE);

    // leading zeros + message type
    const uint16_t REQUEST_MESSAGE_TYPE = htons(0x0001);
    memcpy(stun_request_packet + packet_index, &REQUEST_MESSAGE_TYPE, sizeof(REQUEST_MESSAGE_TYPE));
    packet_index += sizeof(REQUEST_MESSAGE_TYPE);

    // message length (no additional attributes are included)
    uint16_t message_length = 0;
    memcpy(stun_request_packet + packet_index, &message_length, sizeof(message_length));
    packet_index += sizeof(message_length);

    memcpy(stun_request_packet + packet_index, &RFC_5389_MAGIC_COOKIE_NETWORK_ORDER, sizeof(RFC_5389_MAGIC_COOKIE_NETWORK_ORDER));
    packet_index += sizeof(RFC_5389_MAGIC_COOKIE_NETWORK_ORDER);

    // transaction ID (random 12-byte unsigned integer)
    const uint NUM_TRANSACTION_ID_BYTES = 12;
    QUuid randomUUID = QUuid::createUuid();
    memcpy(stun_request_packet + packet_index, randomUUID.toRfc4122().data(), NUM_TRANSACTION_ID_BYTES);

    qDebug () << "HifiConnection::SendStunRequest() - STUN address:" << stun_server_address << "STUN port:" << stun_server_port;
    hifi_socket->writeDatagram(stun_request_packet, NUM_BYTES_STUN_HEADER, stun_server_address, stun_server_port);
}

void HifiConnection::SendIceRequest()
{
    if (num_requests == HIFI_NUM_INITIAL_REQUESTS_BEFORE_FAIL)
    {
        qDebug() << "HifiConnection::SendIceRequest() - Stopping ice requests to" << ice_server_address << ice_server_port;

        ice_response_timer->stop();
        Q_EMIT Disconnected();
        //disconnect(ice_response_timer, &QTimer::timeout, this, &HifiConnection::SendIceRequest);
        //ice_response_timer->deleteLater();
        return;
    }

    if (!has_completed_current_request) {
        qDebug() << "HifiConnection::SendIceRequest() - Sending intial ice request to" << ice_server_address << ice_server_port;

        ++num_requests;
    }
    else {
        //qDebug() << "HifiConnection::SendIceRequest() - Completed ice request";
        //ice_response_timer->stop();
        //disconnect(ice_response_timer, &QTimer::timeout, this, &HifiConnection::SendIceRequest);
        //ice_response_timer->deleteLater();
        return;
    }

    PacketType packetType = PacketType::ICEServerQuery;
    //PacketVersion version = versionForPacketType(packetType);
    std::unique_ptr<Packet> ice_request_packet = Packet::Create(0,packetType);
    QDataStream ice_data_stream(ice_request_packet.get());
    ice_data_stream << ice_client_id << public_address << public_port << local_address << local_port << domain_id;
    //qDebug () << "HifiConnection::SendIceRequest() - ICE address:" << hifi_socket->peerAddress() << "ICE port:" << hifi_socket->peerPort();
    //qDebug() << "ICE packet values" << sequence_number << (uint8_t)packetType << (int)versionForPacketType(packetType) << ice_client_id << public_address << public_port << local_address << local_port << domain_id;

    hifi_socket->writeDatagram(ice_request_packet->GetData(), ice_request_packet->GetDataSize(), ice_server_address, ice_server_port);
}

void HifiConnection::SendDomainIcePing()
{
    if (!finished_domain_id_request) {
        return;
    }

    // send the ping packet to the local and public sockets for this node
    //SendIcePing((quint8) 1);
    SendIcePing((quint8) 2);

    if (messages_mixer) messages_mixer->SendPing();
    if (avatar_mixer) avatar_mixer->SendPing();
    if (audio_mixer) audio_mixer->SendPing();
    if (entity_script_server) entity_script_server->SendPing();
    if (entity_server) entity_server->SendPing();
    if (asset_server) asset_server->SendPing();
}

void HifiConnection::SendDomainConnectRequest()
{
    if (!finished_domain_id_request) {
        return;
    }

    if (num_requests == HIFI_NUM_INITIAL_REQUESTS_BEFORE_FAIL)
    {
            qDebug() << "HifiConnection::SendDomainConnectRequest() - Stopping domain requests to" << domain_place_name;

        hifi_response_timer->stop();
        Q_EMIT Disconnected();
        //hifi_response_timer->deleteLater();
        return;
    }

    if (!domain_connected) {
        qDebug() << "HifiConnection::SendDomainConnectRequest() - Sending initial domain connect request to" << domain_public_address << domain_public_port;
        ++num_requests;
    }
    else {
        //qDebug() << "HifiConnection::SendDomainConnectRequest() - Completed domain connect request";
        //hifi_response_timer->stop();
        //hifi_response_timer->deleteLater();
        return;
    }

    PacketType packet_type = PacketType::DomainConnectRequest;
    //PacketVersion version = versionForPacketType(packetType);
    std::unique_ptr<Packet> domain_connect_request_packet = Packet::Create(sequence_number,packet_type);
    QDataStream domain_connect_data_stream(domain_connect_request_packet.get());
    domain_connect_data_stream << ice_client_id;

    QByteArray protocol_version_sig = Utils::GetProtocolVersionSignature();
    domain_connect_data_stream.writeBytes(protocol_version_sig.constData(), protocol_version_sig.size());

    //qDebug() << ice_client_id << protocol_version_sig << Utils::GetHardwareAddress(hifi_socket->localAddress()) << Utils::GetMachineFingerprint() << (char)owner_type.load()
    //         << public_address << public_port << local_address << local_port << node_types_of_interest << domain_place_name;
    domain_connect_data_stream << Utils::GetHardwareAddress(local_address) << Utils::GetMachineFingerprint()
                            << owner_type.load() << public_address << public_port << local_address << local_port << node_types_of_interest.toList() << domain_place_name; //TODO: user_name_signature

    hifi_socket->writeDatagram(domain_connect_request_packet->GetData(), domain_connect_request_packet->GetDataSize(), domain_public_address, domain_public_port);
    sequence_number++;
}

void HifiConnection::SendIcePing(quint8 ping_type)
{
    int packet_size = NUM_BYTES_RFC4122_UUID + sizeof(quint8);

    auto ice_ping_packet = Packet::Create(sequence_number, PacketType::ICEPing, packet_size);
    ice_ping_packet->write(ice_client_id.toRfc4122());
    ice_ping_packet->write(reinterpret_cast<const char*>(&ping_type), sizeof(ping_type));

    //QByteArray b(ice_ping_packet->GetData(), ice_ping_packet->GetDataSize());
    //qDebug() << "ping packet" << b;

    hifi_socket->writeDatagram(ice_ping_packet->GetData(), ice_ping_packet->GetDataSize(), (ping_type == 1)?domain_local_address:domain_public_address, (ping_type == 1)?domain_local_port:domain_public_port);
    sequence_number++;
}

void HifiConnection::SendIcePingReply(Packet * ice_ping, QHostAddress sender, quint16 sender_port)
{
    quint8 ping_type;

    const char * message = ice_ping->readAll().constData();
    memcpy(&ping_type, message + NUM_BYTES_RFC4122_UUID, sizeof(quint8));

    int packet_size = NUM_BYTES_RFC4122_UUID + sizeof(quint8);
    std::unique_ptr<Packet> ice_ping_reply = Packet::Create(sequence_number, PacketType::ICEPingReply, packet_size);

    // pack the ICE ID and then the ping type
    ice_ping_reply->write(ice_client_id.toRfc4122());
    ice_ping_reply->write(reinterpret_cast<const char*>(&ping_type), sizeof(ping_type));

    //QByteArray b(ice_ping_reply->GetData(), ice_ping_reply->GetDataSize());
    //qDebug() << "ping reply packet" << b;

    //qDebug() << packet_size << ice_ping_reply->GetDataSize();
    hifi_socket->writeDatagram(ice_ping_reply->GetData(), ice_ping_reply->GetDataSize(), sender, sender_port);
    sequence_number++;
}

void HifiConnection::SendHandshakeRequest()
{
    auto handshake_request_packet = Packet::CreateControl(sequence_number, ControlType::HandshakeRequest, 0);
    hifi_socket->writeDatagram(handshake_request_packet->GetData(), handshake_request_packet->GetDataSize(), domain_public_address, domain_public_port);
    QByteArray b(handshake_request_packet->GetData(), handshake_request_packet->GetDataSize());
    bool is_control_packet = *reinterpret_cast<uint32_t*>(handshake_request_packet->GetData()) & CONTROL_BIT_MASK;
    qDebug() << "handshake" << b << is_control_packet;
    did_request_handshake = true;
}

void HifiConnection::ClientMessageReceived(const QString &message)
{
    //qDebug() << "HifiConnection::ClientMessageReceived() - " << message;
    QJsonDocument doc;
    doc = QJsonDocument::fromJson(message.toLatin1());
    QJsonObject obj = doc.object();
    QString type = obj["type"].toString();

    if (type == "domain") {
        // Domain ID lookup
        if (domain_name == "") {
            domain_name = obj["domain_name"].toString();

            if (domain_name.left(7) == "hifi://"){
                domain_name = domain_name.remove("hifi://");
            }

            qDebug() << "HifiConnection::ClientMessageReceived - Looking up domain ID for domain: " << domain_name;

            QNetworkAccessManager * nam = new QNetworkAccessManager(this);
            QNetworkRequest request("https://metaverse.highfidelity.com/api/v1/places/" + domain_name);
            request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
            domain_reply = nam->get(request);
            connect(domain_reply, SIGNAL(finished()), this, SLOT(DomainRequestFinished()));
        }
    }
    else if (type == "offer")
    {
        rtcdcpp::RTCConfiguration config;
        config.ice_servers.emplace_back(rtcdcpp::RTCIceServer{"stun3.l.google.com", 19302});

        std::function<void(rtcdcpp::PeerConnection::IceCandidate)> onLocalIceCandidate = [this](rtcdcpp::PeerConnection::IceCandidate candidate) {
            if (QString::fromStdString(candidate.candidate) != "")
            {
                QJsonObject candidate_object;
                candidate_object.insert("type", QJsonValue::fromVariant("candidate"));
                QJsonObject candidate_object2;
                candidate_object2.insert("candidate", QJsonValue::fromVariant(QString::fromStdString(candidate.candidate)));
                candidate_object2.insert("sdpMid", QJsonValue::fromVariant(QString::fromStdString(candidate.sdpMid)));
                candidate_object2.insert("sdpMLineIndex", QJsonValue::fromVariant(candidate.sdpMLineIndex));
                candidate_object.insert("candidate", candidate_object2);
                QJsonDocument candidateDoc(candidate_object);

                //qDebug() << "candidate: " << candidateDoc.toJson();
                if (this->client_socket)
                    this->client_socket->sendTextMessage(QString::fromStdString(candidateDoc.toJson().toStdString()));
            }
        };

        std::function<void(std::shared_ptr<rtcdcpp::DataChannel> channel)> onDataChannel = [this](std::shared_ptr<rtcdcpp::DataChannel> channel) {
            //qDebug() << "datachannel" << QString::fromStdString(channel->GetLabel());
            QString label = QString::fromStdString(channel->GetLabel());
            if (label == "domain_server_dc") {
                qDebug() << "HifiConnection::onDataChannel() - Registering domain server data channel";
                this->SetDomainServerDC(channel);
            }
            else if (label == "audio_mixer_dc") {
                qDebug() << "HifiConnection::onDataChannel() - Registering audio mixer data channel";
                this->SetAudioMixerDC(channel);
            }
            else if (label == "avatar_mixer_dc") {
                qDebug() << "HifiConnection::onDataChannel() - Registering avatar mixer data channel";
                this->SetAvatarMixerDC(channel);
            }
            else if (label == "entity_server_dc") {
                qDebug() << "HifiConnection::onDataChannel() - Registering entity server data channel";
                this->SetEntityServerDC(channel);
            }
            else if (label == "entity_script_server_dc") {
                qDebug() << "HifiConnection::onDataChannel() - Registering entity script server data channel";
                this->SetEntityScriptServerDC(channel);
            }
            else if (label == "messages_mixer_dc") {
                qDebug() << "HifiConnection::onDataChannel() - Registering messages mixer data channel";
                this->SetMessagesMixerDC(channel);
            }
            else if (label == "asset_server_dc") {
                qDebug() << "HifiConnection::onDataChannel() - Registering asset server data channel";
                this->SetAssetServerDC(channel);
            }

            if (this->DataChannelsReady() && this->finished_domain_id_request) {
                qDebug() << "HifiConnection::WebRTCConnectionReady() - Data channels registered";
                Q_EMIT WebRTCConnectionReady();
            }
        };

        remote_peer_connection = std::make_shared<rtcdcpp::PeerConnection>(config, onLocalIceCandidate, onDataChannel);

        remote_peer_connection->ParseOffer(obj["sdp"].toString().toStdString());
        QJsonObject answer_object;
        answer_object.insert("type", QJsonValue::fromVariant("answer"));
        answer_object.insert("sdp", QJsonValue::fromVariant(QString::fromStdString(remote_peer_connection->GenerateAnswer())));
        QJsonDocument answerDoc(answer_object);

        //qDebug() << "Sending Answer: " << answerDoc.toJson();
        if (this->client_socket)
            client_socket->sendTextMessage(QString::fromStdString(answerDoc.toJson().toStdString()));
    }
    else if (type == "candidate")
    {
        //qDebug() << "remote candidate";
        QJsonObject c = obj["candidate"].toObject();
        remote_peer_connection->SetRemoteIceCandidate("a=" + c["candidate"].toString().toStdString());
    }
}

void HifiConnection::ClientDisconnected()
{
    Q_EMIT Disconnected();
}

void HifiConnection::ServerDisconnected()
{
    Q_EMIT Disconnected();
}

void HifiConnection::NodeDisconnected()
{
    Q_EMIT Disconnected();
}

Node * HifiConnection::GetNodeFromAddress(QHostAddress sender, quint16 sender_port)
{
    Node * node = nullptr;
    if (audio_mixer->CheckNodeAddress(sender, sender_port))
        node = audio_mixer;
    else if (avatar_mixer->CheckNodeAddress(sender, sender_port))
        node = avatar_mixer;
    else if (asset_server->CheckNodeAddress(sender, sender_port))
        node = asset_server;
    else if (messages_mixer->CheckNodeAddress(sender, sender_port))
        node = messages_mixer;
    else if (entity_script_server->CheckNodeAddress(sender, sender_port))
        node = entity_script_server;
    else if (entity_server->CheckNodeAddress(sender, sender_port))
        node = entity_server;

    return node;
}
