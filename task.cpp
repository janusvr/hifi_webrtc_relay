#include "task.h"

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

    connect(this, SIGNAL(stunFinished()), this, SLOT(startIce()));
    connect(this, SIGNAL(iceFinished()), this, SLOT(startDomainConnect()));

    startStun();

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

    qDebug() << "Task::domainRequestFinished() - Domain name" << domain_name;
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

    hifi_socket->bind(local_address, local_port);
    if (!use_custom_ice_server){
        hifi_socket->connectToHost(ice_server_hostname, ice_server_port, QIODevice::ReadWrite, QAbstractSocket::IPv4Protocol);
    }
    else{
        hifi_socket->connectToHost(ice_server_address, ice_server_port, QIODevice::ReadWrite);
    }
    hifi_socket->waitForConnected();

    hifi_response_timer->start();
}

void Task::startDomainConnect()
{
    disconnect(hifi_socket, SIGNAL(readyRead()), this, SLOT(parseIceResponse()));
    connect(hifi_socket, SIGNAL(readyRead()), this, SLOT(parseDomainConnectResponse()));

    num_requests = 0;
    has_completed_current_request = false;

    disconnect(hifi_response_timer, &QTimer::timeout, this, &Task::sendIceRequest);
    hifi_response_timer = new QTimer { this };
    connect(hifi_response_timer, &QTimer::timeout, this, &Task::sendDomainConnectRequest);
    hifi_response_timer->setInterval(HIFI_INITIAL_UPDATE_INTERVAL_MSEC); // 250ms, Qt::CoarseTimer acceptable

    hifi_socket->bind(local_address, local_port);
    hifi_socket->connectToHost(domain_public_address, domain_public_port, QIODevice::ReadWrite);
    hifi_socket->waitForConnected();

    hifi_response_timer->start();
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
        emit iceFinished();
    }
}

void Task::parseDomainConnectResponse()
{
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

    uint32_t sequence_number = 0;
    PacketType packetType = PacketType::ICEServerQuery;
    //PacketVersion version = versionForPacketType(packetType);
    std::unique_ptr<Packet> iceRequestPacket = Packet::create(sequence_number,packetType);
    QDataStream iceDataStream(iceRequestPacket.get());
    iceDataStream << ice_client_id << public_address << public_port << local_address << local_port << domain_id;

    //qDebug() << "ICE packet values" << sequence_number << (uint8_t)packetType << (int)version << ice_client_id << public_address << public_port << local_address << local_port << domain_id;

    hifi_socket->write(iceRequestPacket->getData(), iceRequestPacket->getDataSize());
    //hifi_socket->writeDatagram(iceRequestPacket, packetSize, hifi_socket->peerAddress(), hifi_socket->peerPort());
}

void Task::sendDomainConnectRequest()
{

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
