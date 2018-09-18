#include "task.h"

Task::Task(QObject * parent) :
    QObject(parent),
    client_address(QHostAddress::LocalHost),
    client_port(4444),
    stun_server_hostname("stun.highfidelity.io"),
    stun_server_port(3478),
    ice_server_hostname("ice.highfidelity.com"), //"dev-ice.highfidelity.com";
    ice_server_port(7337)
{
    use_custom_ice_server = false;
    finished_domain_id_request = false;
    started_domain_connect = false;
    ice_client_id = QUuid::createUuid();

    owner_type = NodeType::Agent;
    node_types_of_interest = NodeSet() << NodeType::AudioMixer << NodeType::AvatarMixer << NodeType::EntityServer << NodeType::AssetServer << NodeType::MessagesMixer << NodeType::EntityScriptServer;

    domain_connected = false;
    Utils::SetupTimestamp();
    Utils::SetupProtocolVersionSignatures();

    sequence_number = 0;

    asset_server = nullptr;
    audio_mixer = nullptr;
    avatar_mixer = nullptr;
    messages_mixer = nullptr;
    entity_server = nullptr;
    entity_script_server = nullptr;
}

void Task::processCommandLineArguments(int argc, char * argv[])
{
    for (int i=1; i<argc; ++i) {
        const QString s = QString(argv[i]).toLower();
        if (s.right(7) == "-client" && i+2 < argc) {
            client_address = QHostAddress(QString(argv[i+1]));
            client_port = QString(argv[i+2]).toInt();
            i+=2;
        }
        else if (s.right(7) == "-iceserver" && i+2 < argc) {
            use_custom_ice_server = true;
            ice_server_address = QHostAddress(QString(argv[i+1]));
            ice_server_port = QString(argv[i+2]).toInt();
            i+=2;
        }
        else if (s.right(7) == "-domain" && i+1 < argc) {
            QString d(argv[i+1]);
            if (d.left(7) == "hifi://"){
                domain_name = d.remove("hifi://");
            }
            else{
                domain_name = d;
            }
            i+=2;
        }
        else if (s.right(5) == "-help") {
            qDebug() << "Usage: \n hifi_webrtc_relay [-client address port] [-server address port] [-help]";

            // Just exit after displaying this help message
            exit(0);
        }
    }
}

void Task::run()
{
    // Domain ID lookup
    QNetworkAccessManager * nam = new QNetworkAccessManager(this);
    QNetworkRequest request("https://metaverse.highfidelity.com/api/v1/places/" + domain_name);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    domain_reply = nam->get(request);
    connect(domain_reply, SIGNAL(finished()), this, SLOT(domainRequestFinished()));

    //setup client socket for receiving
    client_socket = new QUdpSocket(this);
    client_socket->bind(QHostAddress::LocalHost, 5555);
    client_socket->connectToHost(client_address, client_port, QIODevice::ReadWrite);
    client_socket->waitForConnected();

    connect(client_socket, SIGNAL(readyRead()), this, SLOT (relayToServer()));
    Node::setClientSocket(client_socket);


    startStun();

    // Application runs indefinitely (until terminated - e.g. Ctrl+C)
    //    emit finished();
}

void Task::relayToServer()
{
    //Event loop calls this function each time client socket is ready for reading
    qDebug() << "Task::relayToServer()";
    qDebug() << "TODO: PARSE PACKET AND SEND TO CORRECT SERVER; CHECK IF NULLPTR FIRST";

    while (client_socket->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(client_socket->pendingDatagramSize());
        QHostAddress sender;
        quint16 senderPort;

        client_socket->readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);
    }
}

void Task::domainRequestFinished()
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
                use_custom_ice_server = true;
            }
        }
        domain_reply->close();
    }

    qDebug() << "Task::domainRequestFinished() - Domain name" << domain_name;
    qDebug() << "Task::domainRequestFinished() - Domain place name" << domain_place_name;
    qDebug() << "Task::domainRequestFinished() - Domain ID" << domain_id;

    finished_domain_id_request = true;
}

void Task::startStun()
{
    hifi_socket = new QUdpSocket(this);
    hifi_socket->connectToHost(stun_server_hostname, stun_server_port, QIODevice::ReadWrite, QAbstractSocket::IPv4Protocol);
    hifi_socket->waitForConnected();

    num_requests = 0;
    has_completed_current_request = false;

    connect(hifi_socket, SIGNAL(readyRead()), this, SLOT(parseStunResponse()));

    hifi_response_timer = new QTimer { this };
    connect(hifi_response_timer, &QTimer::timeout, this, &Task::sendStunRequest);
    hifi_response_timer->setInterval(HIFI_INITIAL_UPDATE_INTERVAL_MSEC); // 250ms, Qt::CoarseTimer acceptable

    hifi_response_timer->start();
}

void Task::startIce()
{
    disconnect(hifi_socket, SIGNAL(readyRead()), this, SLOT(parseStunResponse()));
    connect(hifi_socket, SIGNAL(readyRead()), this, SLOT(parseIceResponse()));

    num_requests = 0;
    has_completed_current_request = false;

    disconnect(hifi_response_timer, &QTimer::timeout, this, &Task::sendStunRequest);
    hifi_response_timer = new QTimer { this };
    connect(hifi_response_timer, &QTimer::timeout, this, &Task::sendIceRequest);
    hifi_response_timer->setInterval(HIFI_INITIAL_UPDATE_INTERVAL_MSEC); // 250ms, Qt::CoarseTimer acceptable

    hifi_socket->bind(local_address, local_port, QAbstractSocket::ShareAddress);
    if (!use_custom_ice_server){
        hifi_socket->connectToHost(ice_server_hostname, ice_server_port, QIODevice::ReadWrite, QAbstractSocket::IPv4Protocol);
    }
    else{
        hifi_socket->connectToHost(ice_server_address, ice_server_port, QIODevice::ReadWrite);
    }
    hifi_socket->waitForConnected();

    hifi_response_timer->start();
}

void Task::startDomainIcePing()
{
    disconnect(hifi_socket, SIGNAL(readyRead()), this, SLOT(parseIceResponse()));
    connect(hifi_socket, SIGNAL(readyRead()), this, SLOT(parseDomainResponse()));

    num_requests = 0;
    has_completed_current_request = false;

    disconnect(hifi_response_timer, &QTimer::timeout, this, &Task::sendIceRequest);
    hifi_ping_timer = new QTimer { this };
    connect(hifi_ping_timer, &QTimer::timeout, this, &Task::sendDomainIcePing);
    hifi_ping_timer->setInterval(HIFI_PING_UPDATE_INTERVAL_MSEC); // 250ms, Qt::CoarseTimer acceptable

    hifi_socket->connectToHost(domain_public_address, domain_public_port, QIODevice::ReadWrite);
    hifi_socket->waitForConnected();

    hifi_ping_timer->start();
}

void Task::startDomainConnect()
{
    started_domain_connect = true;
    num_requests = 0;
    has_completed_current_request = false;

    hifi_response_timer = new QTimer { this };
    connect(hifi_response_timer, &QTimer::timeout, this, &Task::sendDomainConnectRequest);
    hifi_response_timer->setInterval(HIFI_INITIAL_UPDATE_INTERVAL_MSEC); // 250ms, Qt::CoarseTimer acceptable

    hifi_response_timer->start();
}

void Task::parseStunResponse()
{
    //qDebug() << "Task::parseStunResponse()";

    // check the cookie to make sure this is actually a STUN response
    // and read the first attribute and make sure it is a XOR_MAPPED_ADDRESS
    const int NUM_BYTES_MESSAGE_TYPE_AND_LENGTH = 4;
    const uint16_t XOR_MAPPED_ADDRESS_TYPE = htons(0x0020);

    const uint32_t RFC_5389_MAGIC_COOKIE_NETWORK_ORDER = htonl(RFC_5389_MAGIC_COOKIE);

    int attributeStartIndex = NUM_BYTES_STUN_HEADER;

    while (hifi_socket->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(hifi_socket->pendingDatagramSize());
        QHostAddress sender;
        quint16 senderPort;

        hifi_socket->readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);

        if (memcmp(datagram.data() + NUM_BYTES_MESSAGE_TYPE_AND_LENGTH,
                   &RFC_5389_MAGIC_COOKIE_NETWORK_ORDER,
                   sizeof(RFC_5389_MAGIC_COOKIE_NETWORK_ORDER)) != 0) {
            qDebug() << "Task::parseStunResponse() - STUN response cannot be parsed, magic cookie is invalid";
            return;
        }

        // enumerate the attributes to find XOR_MAPPED_ADDRESS_TYPE
        while (attributeStartIndex < datagram.size()) {
            if (memcmp(datagram.data() + attributeStartIndex, &XOR_MAPPED_ADDRESS_TYPE, sizeof(XOR_MAPPED_ADDRESS_TYPE)) == 0) {
                const int NUM_BYTES_STUN_ATTR_TYPE_AND_LENGTH = 4;
                const int NUM_BYTES_FAMILY_ALIGN = 1;
                const uint8_t IPV4_FAMILY_NETWORK_ORDER = htons(0x01) >> 8;

                int byteIndex = attributeStartIndex + NUM_BYTES_STUN_ATTR_TYPE_AND_LENGTH + NUM_BYTES_FAMILY_ALIGN;

                uint8_t addressFamily = 0;
                memcpy(&addressFamily, datagram.data() + byteIndex, sizeof(addressFamily));

                byteIndex += sizeof(addressFamily);

                if (addressFamily == IPV4_FAMILY_NETWORK_ORDER) {
                    // grab the X-Port
                    uint16_t xorMappedPort = 0;
                    memcpy(&xorMappedPort, datagram.data() + byteIndex, sizeof(xorMappedPort));

                    public_port = ntohs(xorMappedPort) ^ (ntohl(RFC_5389_MAGIC_COOKIE_NETWORK_ORDER) >> 16);

                    byteIndex += sizeof(xorMappedPort);

                    // grab the X-Address
                    uint32_t xorMappedAddress = 0;
                    memcpy(&xorMappedAddress, datagram.data() + byteIndex, sizeof(xorMappedAddress));

                    uint32_t stunAddress = ntohl(xorMappedAddress) ^ ntohl(RFC_5389_MAGIC_COOKIE_NETWORK_ORDER);

                    // QHostAddress newPublicAddress(stunAddress);
                    public_address = QHostAddress(stunAddress);

                    qDebug() << "Task::parseStunResponse() - Public address: " << public_address;
                    qDebug() << "Task::parseStunResponse() - Public port: " << public_port;

                    local_address = hifi_socket->localAddress();
                    local_port = hifi_socket->localPort();

                    qDebug() << "Task::parseStunResponse() - Local address: " << local_address;
                    qDebug() << "Task::parseStunResponse() - Local port: " << local_port;

                    hifi_socket->disconnectFromHost();
                    hifi_socket->waitForDisconnected();

                    has_completed_current_request = true;

                    startIce();

                    return;
                }
            } else {
                // push forward attributeStartIndex by the length of this attribute
                const int NUM_BYTES_ATTRIBUTE_TYPE = 2;

                uint16_t attributeLength = 0;
                memcpy(&attributeLength, datagram.data() + attributeStartIndex + NUM_BYTES_ATTRIBUTE_TYPE,
                       sizeof(attributeLength));
                attributeLength = ntohs(attributeLength);

                attributeStartIndex += NUM_BYTES_MESSAGE_TYPE_AND_LENGTH + attributeLength;
            }
        }
    }
}

void Task::parseIceResponse()
{
    while (hifi_socket->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(hifi_socket->pendingDatagramSize());
        QHostAddress sender;
        quint16 senderPort;

        hifi_socket->readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);

        //qDebug() << "Task::parseIceResponse() - read packet from " << sender << ":" << senderPort << " of size " << datagram.size() << " bytes";

        std::unique_ptr<Packet> iceResponsePacket = Packet::fromReceivedPacket(datagram.data(), (qint64) datagram.size(), sender, senderPort);
        QDataStream iceResponseStream(iceResponsePacket.get()->readAll());
        QUuid domain_uuid;
        iceResponseStream >> domain_uuid >> domain_public_address >> domain_public_port >> domain_local_address >> domain_local_port;

        if (domain_uuid != domain_id){
            qDebug() << "Task::parseIceResponse() - Error: Domain ID's do not match " << domain_uuid << domain_id;
        }

        qDebug() << "Task::parseIceResponse() - Domain ID: " << domain_uuid << "Domain Public Address: " << domain_public_address << "Domain Public Port: " << domain_public_port << "Domain Local Address: " << domain_local_address << "Domain Local Port: " << domain_local_port;

        hifi_socket->disconnectFromHost();
        hifi_socket->waitForDisconnected();

        has_completed_current_request = true;
        startDomainIcePing();
    }
}

void Task::parseDomainResponse()
{
    while (hifi_socket->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(hifi_socket->pendingDatagramSize());
        QHostAddress sender;
        quint16 senderPort;

        hifi_socket->readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);

        //qDebug() << "Task::parseDomainResponse() - read packet from " << sender << ":" << senderPort << " of size " << datagram.size() << " bytes";

        std::unique_ptr<Packet> domainResponsePacket = Packet::fromReceivedPacket(datagram.data(), (qint64) datagram.size(), sender, senderPort);
        //qDebug() << "Task::parseDomainResponse() - Packet type" << (int) domainResponsePacket->getType();
        sequence_number = domainResponsePacket->getSequenceNumber();
        if (domainResponsePacket->getType() == PacketType::ICEPing) {
            //qDebug() << "Task::parseDomainResponse() - Send ping reply";
            sendIcePingReply(domainResponsePacket.get());
        }
        else if (domainResponsePacket->getType() == PacketType::ICEPingReply) {
            //qDebug() << "Task::parseDomainResponse() - Process ping reply";
            if (!started_domain_connect) startDomainConnect();
        }
        else if (domainResponsePacket->getType() == PacketType::DomainList) {
            qDebug() << "Task::parseDomainResponse() - Process domain list";
            QDataStream packetStream(domainResponsePacket.get()->readAll());

            // grab the domain's ID from the beginning of the packet
            QUuid domainUUID;
            packetStream >> domainUUID;

            if (domain_connected && domain_id != domainUUID) {
                // Recieved packet from different domain.
                qDebug() << "Task::parseDomainResponse() - Received packet from different domain";
                continue;
            }

            quint16 domain_local_id;
            packetStream >> domain_local_id;

            // pull our owner (ie. session) UUID from the packet, it's always the first thing
            // The short (16 bit) ID comes next.
            packetStream >> session_id;
            packetStream >> local_id;

            // if this was the first domain-server list from this domain, we've now connected
            if (!domain_connected) {
                domain_connected = true;
            }

            // pull the permissions/right/privileges for this node out of the stream
            uint newPermissions;
            packetStream >> newPermissions;
            permissions = (Permissions) newPermissions;

            // Is packet authentication enabled?
            bool isAuthenticated;
            packetStream >> isAuthenticated; //TODO: handle authentication of packets

            //qDebug() << domainUUID << domain_local_id << session_id << local_id << newPermissions << isAuthenticated;

            // pull each node in the packet
            while (packetStream.device()->pos() < domainResponsePacket.get()->getDataSize() - domainResponsePacket.get()->totalHeaderSize()) {
                parseNodeFromPacketStream(packetStream);
            }
        }
        else if (domainResponsePacket->getType() == PacketType::DomainConnectionDenied) {
            uint8_t reasonCode;
            //uint8_t reasonSize;

            domainResponsePacket->read((char *) &reasonCode, sizeof(uint8_t));
            /*domainResponsePacket->read((char *) &reasonSize, sizeof(uint8_t));

            QByteArray utfReason;
            utfReason.resize(reasonSize);
            domainResponsePacket->read(utfReason.data(), reasonSize);

            QString reason = QString::fromUtf8(utfReason.constData(), reasonSize);*/

            qDebug() << "Task::parseDomainResponse() - DomainConnectionDenied - Code: " << reasonCode;  //"Reason: "<< reason;
        }
    }
    return;
}

void Task::sendStunRequest()
{
    if (!finished_domain_id_request) {
        return;
    }

    if (num_requests == HIFI_NUM_INITIAL_REQUESTS_BEFORE_FAIL)
    {
        qDebug() << "Task::sendStunRequest() - Stopping stun requests to" << stun_server_hostname << stun_server_port;
        hifi_response_timer->stop();
        hifi_response_timer->deleteLater();
        return;
    }

    if (!has_completed_current_request) {
        qDebug() << "Task::sendStunRequest() - Sending initial stun request to" << stun_server_hostname << stun_server_port;
        ++num_requests;
    }
    else {
        //qDebug() << "Task::sendStunRequest() - Completed stun request";
        hifi_response_timer->stop();
        hifi_response_timer->deleteLater();
        return;
    }

    char * stunRequestPacket = (char *) malloc(NUM_BYTES_STUN_HEADER);
    makeStunRequestPacket(stunRequestPacket);
    qDebug () << "Task::sendStunRequest() - STUN address:" << hifi_socket->peerAddress() << "STUN port:" << hifi_socket->peerPort();
    hifi_socket->write(stunRequestPacket, NUM_BYTES_STUN_HEADER);
    //hifi_socket->writeDatagram(stunRequestPacket, NUM_BYTES_STUN_HEADER, hifi_socket->peerAddress(), hifi_socket->peerPort());
}

void Task::sendIceRequest()
{
    if (num_requests == HIFI_NUM_INITIAL_REQUESTS_BEFORE_FAIL)
    {
        if (use_custom_ice_server)
            qDebug() << "Task::sendIceRequest() - Stopping ice requests to" << ice_server_address << ice_server_port;
        else
            qDebug() << "Task::sendIceRequest() - Stopping ice requests to" << ice_server_hostname << ice_server_port;

        hifi_response_timer->stop();
        hifi_response_timer->deleteLater();
        return;
    }

    if (!has_completed_current_request) {
        if (use_custom_ice_server)
            qDebug() << "Task::sendIceRequest() - Sending intial ice request to" << ice_server_address << ice_server_port;
        else
            qDebug() << "Task::sendIceRequest() - Sending intial ice request to" << ice_server_hostname << ice_server_port;

        ++num_requests;
    }
    else {
        //qDebug() << "Task::sendIceRequest() - Completed ice request";
        hifi_response_timer->stop();
        hifi_response_timer->deleteLater();
        return;
    }

    PacketType packetType = PacketType::ICEServerQuery;
    //PacketVersion version = versionForPacketType(packetType);
    std::unique_ptr<Packet> iceRequestPacket = Packet::create(sequence_number,packetType);
    QDataStream iceDataStream(iceRequestPacket.get());
    iceDataStream << ice_client_id << public_address << public_port << local_address << local_port << domain_id;
    //qDebug () << "Task::sendIceRequest() - ICE address:" << hifi_socket->peerAddress() << "ICE port:" << hifi_socket->peerPort();
    //qDebug() << "ICE packet values" << sequence_number << (uint8_t)packetType << (int)versionForPacketType(packetType) << ice_client_id << public_address << public_port << local_address << local_port << domain_id;
    hifi_socket->write(iceRequestPacket->getData(), iceRequestPacket->getDataSize());

    //hifi_socket->writeDatagram(iceRequestPacket, packetSize, hifi_socket->peerAddress(), hifi_socket->peerPort());
}

void Task::parseNodeFromPacketStream(QDataStream& packetStream)
{
    // setup variables to read into from QDataStream
    NodeType_t nodeType;
    QUuid nodeUUID, connectionSecretUUID;
    QHostAddress nodePublicAddress, nodeLocalAddress;
    quint16 nodePublicPort, nodeLocalPort;
    uint nodePermissions;
    bool isReplicated;
    quint16 sessionLocalID;

    packetStream >> nodeType >> nodeUUID >> nodePublicAddress >> nodePublicPort >> nodeLocalAddress >> nodeLocalPort >> nodePermissions
        >> isReplicated >> sessionLocalID;

    // if the public socket address is 0 then it's reachable at the same IP
    // as the domain server
    if (nodePublicAddress.isNull()) {
        nodePublicAddress = public_address;
    }

    packetStream >> connectionSecretUUID;

    //qDebug() << (char) nodeType << nodeUUID << nodePublicAddress << nodePublicPort << nodeLocalAddress << nodeLocalPort << nodePermissions
    //          << isReplicated << sessionLocalID << connectionSecretUUID;

    Node * node = new Node();
    node->setNodeID(nodeUUID);
    node->setNodeType(nodeType);
    node->setPublicAddress(nodePublicAddress, nodePublicPort);
    node->setLocalAddress(nodeLocalAddress, nodeLocalPort);
    node->setSessionLocalID(sessionLocalID);
    node->setDomainSessionLocalID(local_id);
    node->setIsReplicated(isReplicated);
    node->setConnectionSecret(connectionSecretUUID);
    node->setPermissions((Permissions) nodePermissions);

    switch (nodeType) {
        case NodeType::AssetServer : {
            qDebug() << "Task::parseNodeFromPacketStream() - Registering asset server" << nodePublicAddress << nodePublicPort;
            asset_server = node;
            break;
        }
        case NodeType::AudioMixer : {
            qDebug() << "Task::parseNodeFromPacketStream() - Registering audio mixer" << nodePublicAddress << nodePublicPort;
            audio_mixer = node;
            break;
        }
        case NodeType::AvatarMixer : {
            qDebug() << "Task::parseNodeFromPacketStream() - Registering avatar mixer" << nodePublicAddress << nodePublicPort;
            avatar_mixer = node;
            break;
        }
        case NodeType::MessagesMixer : {
            qDebug() << "Task::parseNodeFromPacketStream() - Registering messages mixer" << nodePublicAddress << nodePublicPort;
            messages_mixer = node;
            break;
        }
        case NodeType::EntityServer : {
            qDebug() << "Task::parseNodeFromPacketStream() - Registering entity server" << nodePublicAddress << nodePublicPort;
            entity_server = node;
            break;
        }
        case NodeType::EntityScriptServer : {
            qDebug() << "Task::parseNodeFromPacketStream() - Registering entity script server" << nodePublicAddress << nodePublicPort;
            entity_script_server = node;
            break;
        }
        default: {
                break;
        }
    }

    // nodes that are downstream or upstream of our own type are kept alive when we hear about them from the domain server
    // and always have their public socket as their active socket
    //if (node->getType() == NodeType::downstreamType(_ownerType) || node->getType() == NodeType::upstreamType(_ownerType)) {
    //    node->setLastHeardMicrostamp(usecTimestampNow());
        node->activatePublicSocket(local_address, local_port);
        //node->sendPing();
    //}
}

void Task::sendDomainIcePing()
{
    if (!finished_domain_id_request) {
        return;
    }

    if (domain_connected) {
        qDebug() << "Task::sendDomainIcePing() - Stopping ICE server pings";
        hifi_ping_timer->stop();
        hifi_ping_timer->deleteLater();
        return;
    }

    // send the ping packet to the local and public sockets for this node
    //sendIcePing((quint8) 1);
    sendIcePing((quint8) 2);
}

void Task::sendDomainConnectRequest()
{
    if (!finished_domain_id_request) {
        return;
    }

    if (!domain_connected) {
        qDebug() << "Task::sendDomainConnectRequest() - Sending initial domain connect request to" << domain_public_address << domain_public_port;
        ++num_requests;
    }
    else {
        //qDebug() << "Task::sendDomainConnectRequest() - Completed domain connect request";
        hifi_response_timer->stop();
        hifi_response_timer->deleteLater();
        return;
    }

    PacketType packetType = PacketType::DomainConnectRequest;
    //PacketVersion version = versionForPacketType(packetType);
    std::unique_ptr<Packet> domainConnectRequestPacket = Packet::create(sequence_number,packetType);
    QDataStream domainConnectDataStream(domainConnectRequestPacket.get());
    domainConnectDataStream << ice_client_id;

    //QByteArray protocolVersionSig = Utils::GetProtocolVersionSignature();
    //domainConnectDataStream.writeBytes(protocolVersionSig.constData(), protocolVersionSig.size());

    //TODO: fix hardcode protocol version
    QByteArray protocolVersionSig;
    protocolVersionSig.push_back(0xc8);
    protocolVersionSig.push_back(0x4d);
    protocolVersionSig.push_back(0x93);
    protocolVersionSig.push_back(0x15);
    protocolVersionSig.push_back(0x28);
    protocolVersionSig.push_back(0xdd);
    protocolVersionSig.push_back(0x6d);
    protocolVersionSig.push_back(0xa2);
    protocolVersionSig.push_back(0xd4);
    protocolVersionSig.push_back(0x72);
    protocolVersionSig.push_back(0x64);
    protocolVersionSig.push_back(0xcd);
    protocolVersionSig.push_back(0x50);
    protocolVersionSig.push_back(0xf1);
    protocolVersionSig.push_back(0xbb);
    protocolVersionSig.push_back(0xa8);
    domainConnectDataStream.writeBytes(protocolVersionSig.constData(), protocolVersionSig.size());

    //qDebug() << ice_client_id << protocolVersionSig << Utils::GetHardwareAddress(hifi_socket->localAddress()) << Utils::GetMachineFingerprint() << (char)owner_type.load()
    //         << public_address << public_port << local_address << local_port << node_types_of_interest << domain_place_name;
    domainConnectDataStream << Utils::GetHardwareAddress(hifi_socket->localAddress()) << Utils::GetMachineFingerprint()
                            << owner_type.load() << public_address << public_port << local_address << local_port << node_types_of_interest.toList() << domain_place_name; //TODO: user_name_signature

    hifi_socket->write(domainConnectRequestPacket->getData(), domainConnectRequestPacket->getDataSize());
}

void Task::makeStunRequestPacket(char * stunRequestPacket)
{
    int packetIndex = 0;

    const uint32_t RFC_5389_MAGIC_COOKIE_NETWORK_ORDER = htonl(RFC_5389_MAGIC_COOKIE);

    // leading zeros + message type
    const uint16_t REQUEST_MESSAGE_TYPE = htons(0x0001);
    memcpy(stunRequestPacket + packetIndex, &REQUEST_MESSAGE_TYPE, sizeof(REQUEST_MESSAGE_TYPE));
    packetIndex += sizeof(REQUEST_MESSAGE_TYPE);

    // message length (no additional attributes are included)
    uint16_t messageLength = 0;
    memcpy(stunRequestPacket + packetIndex, &messageLength, sizeof(messageLength));
    packetIndex += sizeof(messageLength);

    memcpy(stunRequestPacket + packetIndex, &RFC_5389_MAGIC_COOKIE_NETWORK_ORDER, sizeof(RFC_5389_MAGIC_COOKIE_NETWORK_ORDER));
    packetIndex += sizeof(RFC_5389_MAGIC_COOKIE_NETWORK_ORDER);

    // transaction ID (random 12-byte unsigned integer)
    const uint NUM_TRANSACTION_ID_BYTES = 12;
    QUuid randomUUID = QUuid::createUuid();
    memcpy(stunRequestPacket + packetIndex, randomUUID.toRfc4122().data(), NUM_TRANSACTION_ID_BYTES);
}

void Task::sendIcePing(quint8 pingType)
{
    int packetSize = NUM_BYTES_RFC4122_UUID + sizeof(quint8);

    auto icePingPacket = Packet::create(0, PacketType::ICEPing, packetSize);
    icePingPacket->write(ice_client_id.toRfc4122());
    icePingPacket->write(reinterpret_cast<const char*>(&pingType), sizeof(pingType));

    hifi_socket->write(icePingPacket->getData(), icePingPacket->getDataSize());
}

void Task::sendIcePingReply(Packet * icePing)
{
    quint8 pingType;

    const char * message = icePing->readAll().constData();
    memcpy(&pingType, message + NUM_BYTES_RFC4122_UUID, sizeof(quint8));

    int packetSize = NUM_BYTES_RFC4122_UUID + sizeof(quint8);
    std::unique_ptr<Packet> icePingReply = Packet::create(sequence_number, PacketType::ICEPingReply, packetSize);

    // pack the ICE ID and then the ping type
    icePingReply->write(ice_client_id.toRfc4122());
    icePingReply->write(reinterpret_cast<const char*>(&pingType), sizeof(pingType));

    //qDebug() << packetSize << icePingReply->getDataSize();

    hifi_socket->write(icePingReply->getData(), icePingReply->getDataSize());
}
