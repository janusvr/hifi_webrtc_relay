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
    hasCompletedInitialStun = false;
    numInitialStunRequests = 0;
    hasCompletedInitialIce = false;
    numInitialIceRequests = 0;
    hasTCPCheckedLocalSocket = false;
    iceClientID = QUuid::createUuid();

    networkAccessManager = new QNetworkAccessManager();

    qDebug() << "Task::Task() - Synchronously looking up IP address for hostname" << stun_server_hostname;
    QHostInfo result_stun = QHostInfo::fromName(stun_server_hostname);
    handleLookupResult(result_stun, &stun_server_address);
    qDebug() << "Task::Task() - STUN server IP address: " << stun_server_address;

    qDebug() << "Task::Task() - Synchronously looking up IP address for hostname" << ice_server_hostname;
    QHostInfo result_ice = QHostInfo::fromName(ice_server_hostname);
    handleLookupResult(result_ice, &ice_server_address);
    qDebug() << "Task::Task() - ICE server IP address: " << ice_server_address;

    updateLocalSocket();
}

void Task::updateLocalSocket()
{
    // attempt to use Google's DNS to confirm that local IP
    static const QHostAddress RELIABLE_LOCAL_IP_CHECK_HOST = QHostAddress { "8.8.8.8" };
    static const int RELIABLE_LOCAL_IP_CHECK_PORT = 53;

    QTcpSocket* localIPTestSocket = new QTcpSocket;

    connect(localIPTestSocket, &QTcpSocket::connected, this, &Task::connectedForLocalSocketTest);
    connect(localIPTestSocket, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(errorTestingLocalSocket()));

    // attempt to connect to our reliable host
    localIPTestSocket->connectToHost(RELIABLE_LOCAL_IP_CHECK_HOST, RELIABLE_LOCAL_IP_CHECK_PORT);
}

void Task::connectedForLocalSocketTest()
{
    auto localIPTestSocket = qobject_cast<QTcpSocket*>(sender());

    if (localIPTestSocket) {
        auto localHostAddress = localIPTestSocket->localAddress();

        if (localHostAddress.protocol() == QAbstractSocket::IPv4Protocol) {
            local_address = localHostAddress;

            qDebug() << "Task::connectedForLocalSocketTest() - Local address: " << local_address;

            hasTCPCheckedLocalSocket = true;
        }

        localIPTestSocket->deleteLater();
    }
}

void Task::errorTestingLocalSocket()
{
    auto localIPTestSocket = qobject_cast<QTcpSocket*>(sender());

    if (localIPTestSocket) {

        // error connecting to the test socket - if we've never set our local socket using this test socket
        // then use our possibly updated guessed local address as fallback
        if (!hasTCPCheckedLocalSocket) {
            local_address = getGuessedLocalAddress();

            qDebug() << "Task::errorTestingLocalSocket() - Local address: " << local_address;

            hasTCPCheckedLocalSocket = true;
        }

        localIPTestSocket->deleteLater();;
    }
}


QHostAddress Task::getGuessedLocalAddress()
{
    QHostAddress localAddress;

    foreach(const QNetworkInterface &networkInterface, QNetworkInterface::allInterfaces()) {
        if (networkInterface.flags() & QNetworkInterface::IsUp
            && networkInterface.flags() & QNetworkInterface::IsRunning
            && networkInterface.flags() & ~QNetworkInterface::IsLoopBack) {
            // we've decided that this is the active NIC
            // enumerate it's addresses to grab the IPv4 address
            foreach(const QNetworkAddressEntry &entry, networkInterface.addressEntries()) {
                // make sure it's an IPv4 address that isn't the loopback
                if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol && !entry.ip().isLoopback()) {

                    // set our localAddress and break out
                    localAddress = entry.ip();
                    qDebug() << "Task::getGuessedLocalAddress() - " << localAddress;
                    break;
                }
            }
        }

        if (!localAddress.isNull()) {
            break;
        }
    }

    // return the looked up local address
    return localAddress;
}

void Task::ProcessCommandLineArguments(int argc, char * argv[])
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
        else if (s.right(7) == "-domain" && i+1 < argc) {
            domain_id = QUuid(QString(argv[i+1]));
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
    // Do processing here
    //qDebug() << "Task::run()";

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

    ice_stun_socket = new QUdpSocket(this);
    connect(ice_stun_socket, SIGNAL(readyRead()), this, SLOT(parseStunResponse()));

    stunResponseTimer = new QTimer { this };
    const int STUN_INITIAL_UPDATE_INTERVAL_MSECS = 250;
    connect(stunResponseTimer, &QTimer::timeout, this, &Task::sendStunRequest);
    stunResponseTimer->setInterval(STUN_INITIAL_UPDATE_INTERVAL_MSECS); // 250ms, Qt::CoarseTimer acceptable

    //qDebug() << "Domain ID" << domain_id;

    connect(this, SIGNAL(stunFinished()), this, SLOT(startIce()));

    stunResponseTimer->start();

    // Application runs indefinitely (until terminated - e.g. Ctrl+C)
    //    emit finished();
}

void Task::startIce()
{
    disconnect(ice_stun_socket, SIGNAL(readyRead()), this, SLOT(parseStunResponse()));
    connect(ice_stun_socket, SIGNAL(readyRead()), this, SLOT(parseIceResponse()));

    iceResponseTimer = new QTimer { this };
    const int ICE_INITIAL_UPDATE_INTERVAL_MSECS = 250;
    connect(iceResponseTimer, &QTimer::timeout, this, &Task::sendIceRequest);
    iceResponseTimer->setInterval(ICE_INITIAL_UPDATE_INTERVAL_MSECS); // 250ms, Qt::CoarseTimer acceptable

    iceResponseTimer->start();
}

void Task::handleLookupResult(const QHostInfo& hostInfo, QHostAddress * addr)
{
    if (hostInfo.error() != QHostInfo::NoError) {
        qDebug() << "Task::handleLookupResult() - Lookup failed for" << hostInfo.lookupId() << ":" << hostInfo.errorString();
    } else {
        foreach(const QHostAddress& address, hostInfo.addresses()) {
            // just take the first IPv4 address
            if (address.protocol() == QAbstractSocket::IPv4Protocol) {
                *addr = QHostAddress(address);
                qDebug() << "Task::handleLookupResult() - QHostInfo lookup result for"
                    << hostInfo.hostName() << "with lookup ID" << hostInfo.lookupId() << "is" << address.toString();
                break;
            }
        }
    }
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

                    hasCompletedInitialStun = true;

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
    hasCompletedInitialIce = true;
}

void Task::sendStunRequest()
{
    const int NUM_INITIAL_STUN_REQUESTS_BEFORE_FAIL = 10;

    if (hasTCPCheckedLocalSocket && numInitialStunRequests == 0)
    {
        ice_stun_socket->bind(local_address);
    }
    else
    {
        return;
    }

    if (numInitialStunRequests == NUM_INITIAL_STUN_REQUESTS_BEFORE_FAIL)
    {
        qDebug() << "Task::sendStunRequest() - Stopping stun requests to" << stun_server_hostname << stun_server_address << stun_server_port;
        stunResponseTimer->stop();
        stunResponseTimer->deleteLater();
        return;
    }

    if (!hasCompletedInitialStun) {
        qDebug() << "Task::sendStunRequest() - Sending intial stun request to" << stun_server_hostname << stun_server_address << stun_server_port;
        ++numInitialStunRequests;
    }
    else {
        qDebug() << "Task::sendStunRequest() - Completed stun request";
        stunResponseTimer->stop();
        stunResponseTimer->deleteLater();
        return;
    }

    char * stunRequestPacket = (char *) malloc(NUM_BYTES_STUN_HEADER);
    makeStunRequestPacket(stunRequestPacket);
    ice_stun_socket->writeDatagram(stunRequestPacket, NUM_BYTES_STUN_HEADER, stun_server_address, stun_server_port);
}

void Task::sendIceRequest()
{
    const int NUM_INITIAL_ICE_REQUESTS_BEFORE_FAIL = 10;

    if (!hasTCPCheckedLocalSocket) {
        return;
    }

    if (numInitialIceRequests == NUM_INITIAL_ICE_REQUESTS_BEFORE_FAIL)
    {
        qDebug() << "Task::sendIceRequest() - Stopping ice requests to" << ice_server_hostname << ice_server_address << ice_server_port;
        iceResponseTimer->stop();
        iceResponseTimer->deleteLater();
        return;
    }

    if (!hasCompletedInitialIce) {
        qDebug() << "Task::sendIceRequest() - Sending intial ice request to" << ice_server_hostname << ice_server_address << ice_server_port;
        ++numInitialIceRequests;
    }
    else {
        qDebug() << "Task::sendIceRequest() - Completed ice request";
        iceResponseTimer->stop();
        iceResponseTimer->deleteLater();
        return;
    }

    int packetSize = sizeof(uint8_t) + sizeof(char) + sizeof(iceClientID) + sizeof(public_address) + sizeof(public_port) + sizeof(local_address) + sizeof(public_port) + sizeof(domain_id);
    char * iceRequestPacket = (char *) malloc(packetSize);
    makeIceRequestPacket(iceRequestPacket);
    ice_stun_socket->writeDatagram(iceRequestPacket, packetSize, ice_server_address, ice_server_port);
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
    uint8_t packetType = 23;
    char version = 17;

    int packetIndex = 0;

    memcpy(iceRequestPacket + packetIndex, &packetType, sizeof(packetType));
    packetIndex += sizeof(packetType);

    memcpy(iceRequestPacket + packetIndex, &version, sizeof(version));
    packetIndex += sizeof(version);

    memcpy(iceRequestPacket + packetIndex, &iceClientID, sizeof(iceClientID));
    packetIndex += sizeof(iceClientID);

    memcpy(iceRequestPacket + packetIndex, &public_address, sizeof(public_address));
    packetIndex += sizeof(public_address);

    memcpy(iceRequestPacket + packetIndex, &public_port, sizeof(public_port));
    packetIndex += sizeof(public_port);

    memcpy(iceRequestPacket + packetIndex, &local_address, sizeof(local_address));
    packetIndex += sizeof(local_address);

    memcpy(iceRequestPacket + packetIndex, &public_port, sizeof(public_port));
    packetIndex += sizeof(public_port);

    memcpy(iceRequestPacket + packetIndex, &domain_id, sizeof(domain_id));
    packetIndex += sizeof(domain_id);

    qDebug() << "ICE packet values" <<  packetType << (int)version << iceClientID << public_address << public_port << local_address << public_port << domain_id;
}
