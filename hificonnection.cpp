#include "hificonnection.h"

HifiConnection::HifiConnection(QWebSocket * s)
{
    connect(this, SIGNAL(WebRTCConnectionReady()), this, SLOT(HifiConnect()));

    ice_client_id = QUuid::createUuid();

    started_domain_connect = false;

    owner_type = NodeType::Agent;
    node_types_of_interest = NodeSet() << NodeType::AudioMixer << NodeType::AvatarMixer << NodeType::EntityServer << NodeType::AssetServer << NodeType::MessagesMixer << NodeType::EntityScriptServer;

    domain_connected = false;

    sequence_number = 0;

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

    qDebug() << "HifiConnection::Connect() - New client" << s << ice_client_id << s->peerAddress() << s->peerPort();
    client_socket = s;

    connect(client_socket, &QWebSocket::textMessageReceived, this, &HifiConnection::ClientMessageReceived);
    connect(client_socket, &QWebSocket::disconnected, this, &HifiConnection::ClientDisconnected);

    client_socket->sendTextMessage("connected");
}

HifiConnection::~HifiConnection()
{
    if (client_socket) {
        client_socket->close();
    }

    if (hifi_socket) {
        hifi_socket->close();
    }
}

void HifiConnection::HifiConnect()
{
    StartStun();
}

void HifiConnection::StartStun()
{
    hifi_socket = new QUdpSocket(this);
    hifi_socket->connectToHost(Utils::GetStunServerHostname(), Utils::GetStunServerPort(), QIODevice::ReadWrite, QAbstractSocket::IPv4Protocol);
    hifi_socket->waitForConnected();

    num_requests = 0;
    has_completed_current_request = false;

    connect(hifi_socket, SIGNAL(readyRead()), this, SLOT(ParseStunResponse()));

    hifi_response_timer = new QTimer { this };
    connect(hifi_response_timer, &QTimer::timeout, this, &HifiConnection::SendStunRequest);
    hifi_response_timer->setInterval(HIFI_INITIAL_UPDATE_INTERVAL_MSEC); // 250ms, Qt::CoarseTimer acceptable

    hifi_response_timer->start();
}

void HifiConnection::StartIce()
{
    disconnect(hifi_socket, SIGNAL(readyRead()), this, SLOT(ParseStunResponse()));
    connect(hifi_socket, SIGNAL(readyRead()), this, SLOT(ParseIceResponse()));

    num_requests = 0;
    has_completed_current_request = false;

    disconnect(hifi_response_timer, &QTimer::timeout, this, &HifiConnection::SendStunRequest);
    hifi_response_timer = new QTimer { this };
    connect(hifi_response_timer, &QTimer::timeout, this, &HifiConnection::SendIceRequest);
    hifi_response_timer->setInterval(HIFI_INITIAL_UPDATE_INTERVAL_MSEC); // 250ms, Qt::CoarseTimer acceptable

    hifi_socket->bind(local_address, local_port, QAbstractSocket::ShareAddress);
    if (!Utils::GetUseCustomIceServer()){
        hifi_socket->connectToHost(Utils::GetIceServerHostname(), Utils::GetIceServerPort(), QIODevice::ReadWrite, QAbstractSocket::IPv4Protocol);
    }
    else{
        hifi_socket->connectToHost(Utils::GetIceServerAddress(), Utils::GetIceServerPort(), QIODevice::ReadWrite);
    }
    hifi_socket->waitForConnected();

    hifi_response_timer->start();
}

void HifiConnection::StartDomainIcePing()
{
    disconnect(hifi_socket, SIGNAL(readyRead()), this, SLOT(ParseIceResponse()));
    connect(hifi_socket, SIGNAL(readyRead()), this, SLOT(ParseDomainResponse()));

    num_requests = 0;
    has_completed_current_request = false;

    disconnect(hifi_response_timer, &QTimer::timeout, this, &HifiConnection::SendIceRequest);
    hifi_ping_timer = new QTimer { this };
    connect(hifi_ping_timer, &QTimer::timeout, this, &HifiConnection::SendDomainIcePing);
    hifi_ping_timer->setInterval(HIFI_PING_UPDATE_INTERVAL_MSEC); // 250ms, Qt::CoarseTimer acceptable

    hifi_socket->connectToHost(domain_public_address, domain_public_port, QIODevice::ReadWrite);
    hifi_socket->waitForConnected();

    connect(hifi_socket, SIGNAL(disconnected()), this, SLOT(ServerDisconnected()));

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

    hifi_ping_timer->start();
}

void HifiConnection::StartDomainConnect()
{
    started_domain_connect = true;
    num_requests = 0;
    has_completed_current_request = false;

    hifi_response_timer = new QTimer { this };
    connect(hifi_response_timer, &QTimer::timeout, this, &HifiConnection::SendDomainConnectRequest);
    hifi_response_timer->setInterval(HIFI_INITIAL_UPDATE_INTERVAL_MSEC); // 250ms, Qt::CoarseTimer acceptable

    hifi_response_timer->start();
}

void HifiConnection::ParseStunResponse()
{
    //qDebug() << "HifiConnection::ParseStunResponse()";

    // check the cookie to make sure this is actually a STUN response
    // and read the first attribute and make sure it is a XOR_MAPPED_ADDRESS
    const int NUM_BYTES_MESSAGE_TYPE_AND_LENGTH = 4;
    const uint16_t XOR_MAPPED_ADDRESS_TYPE = htons(0x0020);

    const uint32_t RFC_5389_MAGIC_COOKIE_NETWORK_ORDER = htonl(RFC_5389_MAGIC_COOKIE);

    int attribute_start_index = NUM_BYTES_STUN_HEADER;

    while (hifi_socket->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(hifi_socket->pendingDatagramSize());
        QHostAddress sender;
        quint16 sender_port;

        hifi_socket->readDatagram(datagram.data(), datagram.size(), &sender, &sender_port);

        if (memcmp(datagram.data() + NUM_BYTES_MESSAGE_TYPE_AND_LENGTH,
                   &RFC_5389_MAGIC_COOKIE_NETWORK_ORDER,
                   sizeof(RFC_5389_MAGIC_COOKIE_NETWORK_ORDER)) != 0) {
            qDebug() << "HifiConnection::ParseStunResponse() - STUN response cannot be parsed, magic cookie is invalid";
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

                    qDebug() << "HifiConnection::ParseStunResponse() - Public address: " << public_address;
                    qDebug() << "HifiConnection::ParseStunResponse() - Public port: " << public_port;

                    local_address = hifi_socket->localAddress();
                    local_port = hifi_socket->localPort();

                    qDebug() << "HifiConnection::ParseStunResponse() - Local address: " << local_address;
                    qDebug() << "HifiConnection::ParseStunResponse() - Local port: " << local_port;

                    hifi_socket->disconnectFromHost();
                    hifi_socket->waitForDisconnected();

                    has_completed_current_request = true;

                    StartIce();

                    return;
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
    }
}

void HifiConnection::ParseIceResponse()
{
    while (hifi_socket->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(hifi_socket->pendingDatagramSize());
        QHostAddress sender;
        quint16 sender_port;

        hifi_socket->readDatagram(datagram.data(), datagram.size(), &sender, &sender_port);

        //qDebug() << "HifiConnection::ParseIceResponse() - read packet from " << sender << ":" << sender_port << " of size " << datagram.size() << " bytes";

        std::unique_ptr<Packet> ice_response_packet = Packet::FromReceivedPacket(datagram.data(), (qint64) datagram.size(), sender, sender_port);
        QDataStream ice_response_stream(ice_response_packet.get()->readAll());
        QUuid domain_uuid;
        ice_response_stream >> domain_uuid >> domain_public_address >> domain_public_port >> domain_local_address >> domain_local_port;

        if (domain_uuid != Utils::GetDomainID()){
            qDebug() << "HifiConnection::ParseIceResponse() - Error: Domain ID's do not match " << domain_uuid << Utils::GetDomainID();
        }

        qDebug() << "HifiConnection::ParseIceResponse() - Domain ID: " << domain_uuid << "Domain Public Address: " << domain_public_address << "Domain Public Port: " << domain_public_port << "Domain Local Address: " << domain_local_address << "Domain Local Port: " << domain_local_port;

        hifi_socket->disconnectFromHost();
        hifi_socket->waitForDisconnected();

        has_completed_current_request = true;
        StartDomainIcePing();
    }
}

void HifiConnection::ParseDomainResponse()
{
    while (hifi_socket->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(hifi_socket->pendingDatagramSize());
        QHostAddress sender;
        quint16 sender_port;

        hifi_socket->readDatagram(datagram.data(), datagram.size(), &sender, &sender_port);

        //qDebug() << "HifiConnection::ParseDomainResponse() - read packet from " << sender << ":" << sender_port << " of size " << datagram.size() << " bytes";

        std::unique_ptr<Packet> domain_response_packet = Packet::FromReceivedPacket(datagram.data(), (qint64) datagram.size(), sender, sender_port);
        //qDebug() << "HifiConnection::ParseDomainResponse() - Packet type" << (int) domain_response_packet->GetType();
        sequence_number = domain_response_packet->GetSequenceNumber();
        if (domain_response_packet->GetType() == PacketType::ICEPing) {
            //qDebug() << "HifiConnection::ParseDomainResponse() - Send ping reply";
            SendIcePingReply(domain_response_packet.get());
        }
        else if (domain_response_packet->GetType() == PacketType::ICEPingReply) {
            //qDebug() << "HifiConnection::ParseDomainResponse() - Process ping reply";
            if (!started_domain_connect) StartDomainConnect();
        }
        else if (domain_response_packet->GetType() == PacketType::DomainList) {
            qDebug() << "HifiConnection::ParseDomainResponse() - Process domain list";
            QDataStream packet_stream(domain_response_packet.get()->readAll());

            // grab the domain's ID from the beginning of the packet
            QUuid domain_uuid;
            packet_stream >> domain_uuid;

            if (domain_connected && Utils::GetDomainID() != domain_uuid) {
                // Recieved packet from different domain.
                qDebug() << "HifiConnection::ParseDomainResponse() - Received packet from different domain";
                continue;
            }

            quint16 domain_local_id;
            packet_stream >> domain_local_id;

            // pull our owner (ie. session) UUID from the packet, it's always the first thing
            // The short (16 bit) ID comes next.
            packet_stream >> session_id;
            packet_stream >> local_id;

            // if this was the first domain-server list from this domain, we've now connected
            if (!domain_connected) {
                domain_connected = true;
            }

            // pull the permissions/right/privileges for this node out of the stream
            uint new_permissions;
            packet_stream >> new_permissions;
            permissions = (Permissions) new_permissions;

            // Is packet authentication enabled?
            bool is_authenticated;
            packet_stream >> is_authenticated; //TODO: handle authentication of packets

            //qDebug() << domain_uuid << domain_local_id << session_id << local_id << new_permissions << is_authenticated;

            // pull each node in the packet
            while (packet_stream.device()->pos() < domain_response_packet.get()->GetDataSize() - domain_response_packet.get()->TotalHeaderSize()) {
                ParseNodeFromPacketStream(packet_stream);
            }

            // Relay domain list packet over to client
            SendDomainServerDCMessage(datagram);
        }
        else if (domain_response_packet->GetType() == PacketType::DomainConnectionDenied) {
            uint8_t reasonCode;
            //uint8_t reasonSize;

            domain_response_packet->read((char *) &reasonCode, sizeof(uint8_t));
            /*domain_response_packet->read((char *) &reasonSize, sizeof(uint8_t));

            QByteArray utfReason;
            utfReason.resize(reasonSize);
            domain_response_packet->read(utfReason.data(), reasonSize);

            QString reason = QString::fromUtf8(utfReason.constData(), reasonSize);*/

            qDebug() << "HifiConnection::ParseDomainResponse() - DomainConnectionDenied - Code: " << reasonCode;  //"Reason: "<< reason;
        }
        else {
            // Send any other types of packets from the domain server to the client
            SendDomainServerDCMessage(datagram);
        }
    }
    return;
}

void HifiConnection::SendStunRequest()
{
    if (!Utils::GetFinishedDomainIDRequest()) {
        return;
    }

    if (num_requests == HIFI_NUM_INITIAL_REQUESTS_BEFORE_FAIL)
    {
        qDebug() << "HifiConnection::SendStunRequest() - Stopping stun requests to" << Utils::GetStunServerHostname() << Utils::GetStunServerPort();
        hifi_response_timer->stop();
        hifi_response_timer->deleteLater();
        return;
    }

    if (!has_completed_current_request) {
        qDebug() << "HifiConnection::SendStunRequest() - Sending initial stun request to" << Utils::GetStunServerHostname() << Utils::GetStunServerPort();
        ++num_requests;
    }
    else {
        //qDebug() << "HifiConnection::SendStunRequest() - Completed stun request";
        hifi_response_timer->stop();
        hifi_response_timer->deleteLater();
        return;
    }

    char * stun_request_packet = (char *) malloc(NUM_BYTES_STUN_HEADER);
    MakeStunRequestPacket(stun_request_packet);
    qDebug () << "HifiConnection::SendStunRequest() - STUN address:" << hifi_socket->peerAddress() << "STUN port:" << hifi_socket->peerPort();
    hifi_socket->write(stun_request_packet, NUM_BYTES_STUN_HEADER);
    //hifi_socket->writeDatagram(stun_request_packet, NUM_BYTES_STUN_HEADER, hifi_socket->peerAddress(), hifi_socket->peerPort());
}

void HifiConnection::SendIceRequest()
{
    if (num_requests == HIFI_NUM_INITIAL_REQUESTS_BEFORE_FAIL)
    {
        if (Utils::GetUseCustomIceServer())
            qDebug() << "HifiConnection::SendIceRequest() - Stopping ice requests to" << Utils::GetIceServerAddress() << Utils::GetIceServerPort();
        else
            qDebug() << "HifiConnection::SendIceRequest() - Stopping ice requests to" << Utils::GetIceServerHostname() << Utils::GetIceServerPort();

        hifi_response_timer->stop();
        hifi_response_timer->deleteLater();
        return;
    }

    if (!has_completed_current_request) {
        if (Utils::GetUseCustomIceServer())
            qDebug() << "HifiConnection::SendIceRequest() - Sending intial ice request to" << Utils::GetIceServerAddress() << Utils::GetIceServerPort();
        else
            qDebug() << "HifiConnection::SendIceRequest() - Sending intial ice request to" << Utils::GetIceServerHostname() << Utils::GetIceServerPort();

        ++num_requests;
    }
    else {
        //qDebug() << "HifiConnection::SendIceRequest() - Completed ice request";
        hifi_response_timer->stop();
        hifi_response_timer->deleteLater();
        return;
    }

    PacketType packetType = PacketType::ICEServerQuery;
    //PacketVersion version = versionForPacketType(packetType);
    std::unique_ptr<Packet> ice_request_packet = Packet::Create(sequence_number,packetType);
    QDataStream ice_data_stream(ice_request_packet.get());
    ice_data_stream << ice_client_id << public_address << public_port << local_address << local_port << Utils::GetDomainID();
    //qDebug () << "HifiConnection::SendIceRequest() - ICE address:" << hifi_socket->peerAddress() << "ICE port:" << hifi_socket->peerPort();
    //qDebug() << "ICE packet values" << sequence_number << (uint8_t)packetType << (int)versionForPacketType(packetType) << ice_client_id << public_address << public_port << local_address << local_port << Utils::GetDomainID();
    hifi_socket->write(ice_request_packet->GetData(), ice_request_packet->GetDataSize());

    //hifi_socket->writeDatagram(ice_request_packet, packetSize, hifi_socket->peerAddress(), hifi_socket->peerPort());
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
        >> is_replicated >> session_local_id;

    // if the public socket address is 0 then it's reachable at the same IP
    // as the domain server
    if (node_public_address.isNull()) {
        node_public_address = public_address;
    }

    packet_stream >> connection_secret_uuid;

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

    switch (node_type) {
        case NodeType::AssetServer : {
            qDebug() << "HifiConnection::ParseNodeFromPacketStream() - Registering asset server" << node_public_address << node_public_port;
            asset_server = node;
            asset_server->SetDataChannel(asset_server_dc);
            connect(asset_server, SIGNAL(Disconnected()), this, SLOT(NodeDisconnected()));
            break;
        }
        case NodeType::AudioMixer : {
            qDebug() << "HifiConnection::ParseNodeFromPacketStream() - Registering audio mixer" << node_public_address << node_public_port;
            audio_mixer = node;
            audio_mixer->SetDataChannel(audio_mixer_dc);
            connect(audio_mixer, SIGNAL(Disconnected()), this, SLOT(NodeDisconnected()));
            break;
        }
        case NodeType::AvatarMixer : {
            qDebug() << "HifiConnection::ParseNodeFromPacketStream() - Registering avatar mixer" << node_public_address << node_public_port;
            avatar_mixer = node;
            avatar_mixer->SetDataChannel(avatar_mixer_dc);
            connect(avatar_mixer, SIGNAL(Disconnected()), this, SLOT(NodeDisconnected()));
            break;
        }
        case NodeType::MessagesMixer : {
            qDebug() << "HifiConnection::ParseNodeFromPacketStream() - Registering messages mixer" << node_public_address << node_public_port;
            messages_mixer = node;
            messages_mixer->SetDataChannel(messages_mixer_dc);
            connect(messages_mixer, SIGNAL(Disconnected()), this, SLOT(NodeDisconnected()));
            break;
        }
        case NodeType::EntityServer : {
            qDebug() << "HifiConnection::ParseNodeFromPacketStream() - Registering entity server" << node_public_address << node_public_port;
            entity_server = node;
            entity_server->SetDataChannel(entity_server_dc);
            connect(entity_server, SIGNAL(Disconnected()), this, SLOT(NodeDisconnected()));
            break;
        }
        case NodeType::EntityScriptServer : {
            qDebug() << "HifiConnection::ParseNodeFromPacketStream() - Registering entity script server" << node_public_address << node_public_port;
            entity_script_server = node;
            entity_script_server->SetDataChannel(entity_script_server_dc);
            connect(entity_script_server, SIGNAL(Disconnected()), this, SLOT(NodeDisconnected()));
            break;
        }
        default: {
                break;
        }
    }

    // nodes that are downstream or upstream of our own type are kept alive when we hear about them from the domain server
    // and always have their public socket as their active socket
    //if (node->GetType() == NodeType::downstreamType(_ownerType) || node->GetType() == NodeType::upstreamType(_ownerType)) {
    //    node->setLastHeardMicrostamp(usecTimestampNow());
        node->ActivatePublicSocket(local_address, local_port);
        //node->sendPing();
    //}
}

void HifiConnection::SendDomainIcePing()
{
    if (!Utils::GetFinishedDomainIDRequest()) {
        return;
    }

    if (num_requests == 2000 / HIFI_PING_UPDATE_INTERVAL_MSEC)
    {
        qDebug() << "HifiConnection::SendDomainIcePing() - Stopping domain ice ping requests to" << Utils::GetDomainPlaceName();

        hifi_ping_timer->stop();
        hifi_ping_timer->deleteLater();
        return;
    }

    if (domain_connected) {
        qDebug() << "HifiConnection::SendDomainIcePing() - Stopping ICE server pings";
        hifi_ping_timer->stop();
        hifi_ping_timer->deleteLater();
        return;
    }

    // send the ping packet to the local and public sockets for this node
    //SendIcePing((quint8) 1);
    SendIcePing((quint8) 2);
}

void HifiConnection::SendDomainConnectRequest()
{
    if (!Utils::GetFinishedDomainIDRequest()) {
        return;
    }

    if (num_requests == HIFI_NUM_INITIAL_REQUESTS_BEFORE_FAIL)
    {
            qDebug() << "HifiConnection::SendDomainConnectRequest() - Stopping domain requests to" << Utils::GetDomainPlaceName();

        hifi_response_timer->stop();
        hifi_response_timer->deleteLater();
        return;
    }

    if (!domain_connected) {
        qDebug() << "HifiConnection::SendDomainConnectRequest() - Sending initial domain connect request to" << domain_public_address << domain_public_port;
        ++num_requests;
    }
    else {
        //qDebug() << "HifiConnection::SendDomainConnectRequest() - Completed domain connect request";
        hifi_response_timer->stop();
        hifi_response_timer->deleteLater();
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
    //         << public_address << public_port << local_address << local_port << node_types_of_interest << Utils::GetDomainPlaceName();
    domain_connect_data_stream << Utils::GetHardwareAddress(hifi_socket->localAddress()) << Utils::GetMachineFingerprint()
                            << owner_type.load() << public_address << public_port << local_address << local_port << node_types_of_interest.toList() << Utils::GetDomainPlaceName(); //TODO: user_name_signature

    hifi_socket->write(domain_connect_request_packet->GetData(), domain_connect_request_packet->GetDataSize());
}

void HifiConnection::MakeStunRequestPacket(char * stun_request_packet)
{
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
}

void HifiConnection::SendIcePing(quint8 ping_type)
{
    int packet_size = NUM_BYTES_RFC4122_UUID + sizeof(quint8);

    auto ice_ping_packet = Packet::Create(0, PacketType::ICEPing, packet_size);
    ice_ping_packet->write(ice_client_id.toRfc4122());
    ice_ping_packet->write(reinterpret_cast<const char*>(&ping_type), sizeof(ping_type));

    hifi_socket->write(ice_ping_packet->GetData(), ice_ping_packet->GetDataSize());
}

void HifiConnection::SendIcePingReply(Packet * ice_ping)
{
    quint8 ping_type;

    const char * message = ice_ping->readAll().constData();
    memcpy(&ping_type, message + NUM_BYTES_RFC4122_UUID, sizeof(quint8));

    int packet_size = NUM_BYTES_RFC4122_UUID + sizeof(quint8);
    std::unique_ptr<Packet> ice_ping_reply = Packet::Create(sequence_number, PacketType::ICEPingReply, packet_size);

    // pack the ICE ID and then the ping type
    ice_ping_reply->write(ice_client_id.toRfc4122());
    ice_ping_reply->write(reinterpret_cast<const char*>(&ping_type), sizeof(ping_type));

    //qDebug() << packet_size << ice_ping_reply->GetDataSize();

    hifi_socket->write(ice_ping_reply->GetData(), ice_ping_reply->GetDataSize());
}

void HifiConnection::ClientMessageReceived(const QString &message)
{
    //qDebug() << "HifiConnection::ClientMessageReceived() - " << message;
    QJsonDocument doc;
    doc = QJsonDocument::fromJson(message.toLatin1());
    QJsonObject obj = doc.object();
    QString type = obj["type"].toString();
    if (type == "offer")
    {
        rtcdcpp::RTCConfiguration config;
        config.ice_servers.emplace_back(rtcdcpp::RTCIceServer{"stun3.l.google.com", 19302});

        std::function<void(rtcdcpp::PeerConnection::IceCandidate)> onLocalIceCandidate = [this](rtcdcpp::PeerConnection::IceCandidate candidate) {
            QJsonObject candidate_object;
            candidate_object.insert("type", QJsonValue::fromVariant("candidate"));
            QJsonObject candidate_object2;
            candidate_object2.insert("candidate", QJsonValue::fromVariant(QString::fromStdString(candidate.candidate)));
            candidate_object2.insert("sdpMid", QJsonValue::fromVariant(QString::fromStdString(candidate.sdpMid)));
            candidate_object2.insert("sdpMLineIndex", QJsonValue::fromVariant(candidate.sdpMLineIndex));
            candidate_object.insert("candidate", candidate_object2);
            QJsonDocument candidateDoc(candidate_object);

            //qDebug() << "candidate: " << candidateDoc.toJson();
            this->client_socket->sendTextMessage(QString::fromStdString(candidateDoc.toJson().toStdString()));
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

            if (this->DataChannelsReady()) {
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
