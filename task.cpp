#include "task.h"

PacketVersion versionForPacketType(PacketType packetType) {
    switch (packetType) {
        case PacketType::StunResponse:
            return 17;
        case PacketType::DomainList:
            return static_cast<PacketVersion>(DomainListVersion::AuthenticationOptional);
        case PacketType::EntityAdd:
        case PacketType::EntityClone:
        case PacketType::EntityEdit:
        case PacketType::EntityData:
        case PacketType::EntityPhysics:
            return static_cast<PacketVersion>(EntityVersion::BloomEffect);
        case PacketType::EntityQuery:
            return static_cast<PacketVersion>(EntityQueryPacketVersion::ConicalFrustums);
        case PacketType::AvatarIdentity:
        case PacketType::AvatarData:
        case PacketType::BulkAvatarData:
        case PacketType::KillAvatar:
            return static_cast<PacketVersion>(AvatarMixerPacketVersion::MigrateAvatarEntitiesToTraits);
        case PacketType::MessagesData:
            return static_cast<PacketVersion>(MessageDataVersion::TextOrBinaryData);
        // ICE packets
        case PacketType::ICEServerPeerInformation:
            return 17;
        case PacketType::ICEServerHeartbeatACK:
            return 17;
        case PacketType::ICEServerQuery:
            return 17;
        case PacketType::ICEServerHeartbeat:
            return 18; // ICE Server Heartbeat signing
        case PacketType::ICEPing:
            return static_cast<PacketVersion>(IcePingVersion::SendICEPeerID);
        case PacketType::ICEPingReply:
            return 17;
        case PacketType::ICEServerHeartbeatDenied:
            return 17;
        case PacketType::AssetMappingOperation:
        case PacketType::AssetMappingOperationReply:
        case PacketType::AssetGetInfo:
        case PacketType::AssetGet:
        case PacketType::AssetUpload:
            return static_cast<PacketVersion>(AssetServerPacketVersion::BakingTextureMeta);
        case PacketType::NodeIgnoreRequest:
            return 18; // Introduction of node ignore request (which replaced an unused packet tpye)

        case PacketType::DomainConnectionDenied:
            return static_cast<PacketVersion>(DomainConnectionDeniedVersion::IncludesExtraInfo);

        case PacketType::DomainConnectRequest:
            return static_cast<PacketVersion>(DomainConnectRequestVersion::AlwaysHasMachineFingerprint);

        case PacketType::DomainServerAddedNode:
            return static_cast<PacketVersion>(DomainServerAddedNodeVersion::PermissionsGrid);

        case PacketType::EntityScriptCallMethod:
            return static_cast<PacketVersion>(EntityScriptCallMethodVersion::ClientCallable);

        case PacketType::MixedAudio:
        case PacketType::SilentAudioFrame:
        case PacketType::InjectAudio:
        case PacketType::MicrophoneAudioNoEcho:
        case PacketType::MicrophoneAudioWithEcho:
        case PacketType::AudioStreamStats:
            return static_cast<PacketVersion>(AudioVersion::HighDynamicRangeVolume);
        case PacketType::DomainSettings:
            return 18;  // replace min_avatar_scale and max_avatar_scale with min_avatar_height and max_avatar_height
        case PacketType::Ping:
            return static_cast<PacketVersion>(PingVersion::IncludeConnectionID);
        case PacketType::AvatarQuery:
            return static_cast<PacketVersion>(AvatarQueryVersion::ConicalFrustums);
        case PacketType::AvatarIdentityRequest:
            return 22;
        case PacketType::EntityQueryInitialResultsComplete:
            return static_cast<PacketVersion>(EntityVersion::ParticleSpin);
        default:
            return 22;
    }
}

uint qHash(const PacketType& key, uint seed) {
    // seems odd that Qt couldn't figure out this cast itself, but this fixes a compile error after switch
    // to strongly typed enum for PacketType
    return qHash((quint8) key, seed);
}

Task::Task(QObject * parent) :
    QObject(parent),
    client_address(QHostAddress::LocalHost),
    client_port(4444),
    server_address(QHostAddress::LocalHost),
    server_port(5555),
    stun_server_hostname("stun.highfidelity.io"),
    stun_server_port(3478),
    ice_server_hostname("ice.highfidelity.com"), //"dev-ice.highfidelity.com";
    ice_server_port(7337)
{
    has_completed_initial_stun = false;
    num_initial_stun_requests = 0;
    has_completed_initial_ice = false;
    num_initial_ice_requests = 0;
    use_custom_ice_server = false;
    finished_domain_id_request = false;
    ice_client_id = QUuid::createUuid();
}

void Task::processCommandLineArguments(int argc, char * argv[])
{
    for (int i=1; i<argc; ++i) {
        const QString s = QString(argv[i]).toLower();
        if (s.right(7) == "-server" && i+2 < argc) {
            server_address = QHostAddress(QString(argv[i+1]));
            server_port = QString(argv[i+2]).toInt();
            i+=2;
        }
        else if (s.right(7) == "-client" && i+2 < argc) {
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
    client_socket->bind(QHostAddress::LocalHost, 6666);

    //setup hifi server socket for sending
    server_socket = new QUdpSocket(this);
    server_socket->bind(QHostAddress::LocalHost, 7777);

    signal_mapper = new QSignalMapper(this);
    signal_mapper->setMapping(client_socket, QString("client"));
    signal_mapper->setMapping(server_socket, QString("server"));

    connect(client_socket, SIGNAL(readyRead()), signal_mapper, SLOT (map()));
    connect(server_socket, SIGNAL(readyRead()), signal_mapper, SLOT (map()));

    connect(signal_mapper, SIGNAL(mapped(QString)), this, SLOT(readPendingDatagrams(QString)));

    // STUN server request
    ice_stun_socket = new QUdpSocket(this);
    ice_stun_socket->connectToHost(stun_server_hostname, stun_server_port, QIODevice::ReadWrite, QAbstractSocket::IPv4Protocol);
    ice_stun_socket->waitForConnected();

    connect(ice_stun_socket, SIGNAL(readyRead()), this, SLOT(parseStunResponse()));

    stun_response_timer = new QTimer { this };
    const int STUN_INITIAL_UPDATE_INTERVAL_MSECS = 250;
    connect(stun_response_timer, &QTimer::timeout, this, &Task::sendStunRequest);
    stun_response_timer->setInterval(STUN_INITIAL_UPDATE_INTERVAL_MSECS); // 250ms, Qt::CoarseTimer acceptable

    connect(this, SIGNAL(stunFinished()), this, SLOT(startIce()));

    stun_response_timer->start();

    // Application runs indefinitely (until terminated - e.g. Ctrl+C)
    //    emit finished();
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

            if (domain.contains("ice_server_address")) {
                ice_server_address = QHostAddress(domain["ice_server_address"].toString());
                use_custom_ice_server = true;
            }
        }
        domain_reply->close();
    }

    qDebug() << "Domain name" << domain_name;
    qDebug() << "Domain ID" << domain_id;

    finished_domain_id_request = true;
}

void Task::startIce()
{
    disconnect(ice_stun_socket, SIGNAL(readyRead()), this, SLOT(parseStunResponse()));
    connect(ice_stun_socket, SIGNAL(readyRead()), this, SLOT(parseIceResponse()));

    ice_response_timer = new QTimer { this };
    const int ICE_INITIAL_UPDATE_INTERVAL_MSECS = 250;
    connect(ice_response_timer, &QTimer::timeout, this, &Task::sendIceRequest);
    ice_response_timer->setInterval(ICE_INITIAL_UPDATE_INTERVAL_MSECS); // 250ms, Qt::CoarseTimer acceptable

    ice_stun_socket->bind(local_address, local_port);
    if (!use_custom_ice_server){
        ice_stun_socket->connectToHost(ice_server_hostname, ice_server_port, QIODevice::ReadWrite, QAbstractSocket::IPv4Protocol);
    }
    else{
        ice_stun_socket->connectToHost(ice_server_address, ice_server_port, QIODevice::ReadWrite);
    }
    ice_stun_socket->waitForConnected();

    ice_response_timer->start();
}

void Task::readPendingDatagrams(QString f)
{
    //Event loop calls this function each time client socket is ready for reading
    qDebug() << "Task::readPendingDatagrams()";

    QUdpSocket * from = (f == "client") ? client_socket : server_socket;
    QUdpSocket * to = (f == "client") ? server_socket : client_socket;
    QHostAddress address = (f == "client") ? server_address : client_address;
    quint16 port = (f == "client") ? server_port : client_port;

    while (from->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(from->pendingDatagramSize());
        QHostAddress sender;
        quint16 senderPort;

        from->readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);

        //Output debug information (for debug builds, not for production release)
        qDebug() << "Task::readPendingDatagrams() - read packet from " << sender << f << ":" << senderPort << " of size " << datagram.size() << " bytes";

        to->writeDatagram(datagram, address, port);
    }
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

    while (ice_stun_socket->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(ice_stun_socket->pendingDatagramSize());
        QHostAddress sender;
        quint16 senderPort;

        ice_stun_socket->readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);

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

                    local_address = ice_stun_socket->localAddress();
                    local_port = ice_stun_socket->localPort();

                    qDebug() << "Task::parseStunResponse() - Local address: " << local_address;
                    qDebug() << "Task::parseStunResponse() - Local port: " << local_port;

                    ice_stun_socket->disconnectFromHost();
                    ice_stun_socket->waitForDisconnected();

                    has_completed_initial_stun = true;

                    emit stunFinished();

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
    qDebug() << "ICE RESPONSE";
    has_completed_initial_ice = true;
}

void Task::sendStunRequest()
{
    const int NUM_INITIAL_STUN_REQUESTS_BEFORE_FAIL = 10;

    if (!finished_domain_id_request) {
        return;
    }

    if (num_initial_stun_requests == NUM_INITIAL_STUN_REQUESTS_BEFORE_FAIL)
    {
        qDebug() << "Task::sendStunRequest() - Stopping stun requests to" << stun_server_hostname << stun_server_port;
        stun_response_timer->stop();
        stun_response_timer->deleteLater();
        return;
    }

    if (!has_completed_initial_stun) {
        qDebug() << "Task::sendStunRequest() - Sending initial stun request to" << stun_server_hostname << stun_server_port;
        ++num_initial_stun_requests;
    }
    else {
        qDebug() << "Task::sendStunRequest() - Completed stun request";
        stun_response_timer->stop();
        stun_response_timer->deleteLater();
        return;
    }

    char * stunRequestPacket = (char *) malloc(NUM_BYTES_STUN_HEADER);
    makeStunRequestPacket(stunRequestPacket);
    qDebug () << "Task::sendStunRequest() - STUN address:" << ice_stun_socket->peerAddress() << "STUN port:" << ice_stun_socket->peerPort();
    ice_stun_socket->write(stunRequestPacket, NUM_BYTES_STUN_HEADER);
    //ice_stun_socket->writeDatagram(stunRequestPacket, NUM_BYTES_STUN_HEADER, ice_stun_socket->peerAddress(), ice_stun_socket->peerPort());
}

void Task::sendIceRequest()
{
    const int NUM_INITIAL_ICE_REQUESTS_BEFORE_FAIL = 10;

    if (num_initial_ice_requests == NUM_INITIAL_ICE_REQUESTS_BEFORE_FAIL)
    {
        if (use_custom_ice_server)
            qDebug() << "Task::sendIceRequest() - Stopping ice requests to" << ice_server_address << ice_server_port;
        else
            qDebug() << "Task::sendIceRequest() - Stopping ice requests to" << ice_server_hostname << ice_server_port;

        ice_response_timer->stop();
        ice_response_timer->deleteLater();
        return;
    }

    if (!has_completed_initial_ice) {
        if (use_custom_ice_server)
            qDebug() << "Task::sendIceRequest() - Sending intial ice request to" << ice_server_address << ice_server_port;
        else
            qDebug() << "Task::sendIceRequest() - Sending intial ice request to" << ice_server_hostname << ice_server_port;

        ++num_initial_ice_requests;
    }
    else {
        qDebug() << "Task::sendIceRequest() - Completed ice request";
        ice_response_timer->stop();
        ice_response_timer->deleteLater();
        return;
    }

    int packetSize = sizeof(PacketType) + sizeof(PacketVersion) + sizeof(QUuid) + sizeof(QHostAddress) + sizeof(quint16) + sizeof(QHostAddress) + sizeof(quint16) + sizeof(QUuid);
    char * iceRequestPacket = (char *) malloc(packetSize);
    makeIceRequestPacket(iceRequestPacket);
    qDebug () << "Task::sendIceRequest() - ICE address:" << ice_stun_socket->peerAddress() << "ICE port:" << ice_stun_socket->peerPort();
    ice_stun_socket->write(iceRequestPacket, packetSize);
    //ice_stun_socket->writeDatagram(iceRequestPacket, packetSize, ice_stun_socket->peerAddress(), ice_stun_socket->peerPort());
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

void Task::makeIceRequestPacket(char * iceRequestPacket)
{
    PacketType packetType = PacketType::ICEServerQuery;
    PacketVersion version = versionForPacketType(packetType);

    int packetIndex = 0;

    memcpy(iceRequestPacket + packetIndex, &packetType, sizeof(PacketType));
    packetIndex += sizeof(PacketType);

    memcpy(iceRequestPacket + packetIndex, &version, sizeof(PacketVersion));
    packetIndex += sizeof(PacketVersion);

    memcpy(iceRequestPacket + packetIndex, &ice_client_id, sizeof(QUuid));
    packetIndex += sizeof(QUuid);

    memcpy(iceRequestPacket + packetIndex, &public_address, sizeof(QHostAddress));
    packetIndex += sizeof(QHostAddress);

    memcpy(iceRequestPacket + packetIndex, &public_port, sizeof(quint16));
    packetIndex += sizeof(quint16);

    memcpy(iceRequestPacket + packetIndex, &local_address, sizeof(QHostAddress));
    packetIndex += sizeof(QHostAddress);

    memcpy(iceRequestPacket + packetIndex, &local_port, sizeof(quint16));
    packetIndex += sizeof(quint16);

    memcpy(iceRequestPacket + packetIndex, &domain_id, sizeof(QUuid));
    packetIndex += sizeof(QUuid);

    //qDebug() << "ICE packet values" <<  uint8_t(packetType) << (int)version << ice_client_id << public_address << public_port << local_address << local_port << domain_id;
}
