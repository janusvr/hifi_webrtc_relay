#include "packet.h"

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

Packet::Packet(uint32_t sequence, PacketType t, qint64 size)
{
    type = t;
    version = versionForPacketType(t);

    packetSize = size;
    payloadSize = 0;
    payloadCapacity = packetSize;
    packet.reset(new char[packetSize]());
    payloadStart = packet.get();
    sequenceNumber = sequence;

    // Pack the sequence number
    memcpy(packet.get(), &sequenceNumber, sizeof(uint32_t));

    // Pack the packet type
    memcpy(packet.get() + sizeof(uint32_t), &type, sizeof(PacketType));

    // Pack the packet version
    memcpy(packet.get() + sizeof(uint32_t) + sizeof(PacketType), &version, sizeof(PacketVersion));

    adjustPayloadStartAndCapacity(Packet::headerSize(false) + Packet::localHeaderSize(type));
}

Packet::Packet(char * data, qint64 size, QHostAddress addr, quint16 port)
{
    packetSize = size;

    packet.reset(new char[size]());
    memcpy(packet.get(),data,size);

    payloadStart = packet.get();
    payloadCapacity = size;
    payloadSize = size;

    uint32_t* seqNumBitField = reinterpret_cast<uint32_t*>(packet.get());

    bool isReliable = (bool) (*seqNumBitField & RELIABILITY_BIT_MASK); // Only keep reliability bit
    bool isPartOfMessage = (bool) (*seqNumBitField & MESSAGE_BIT_MASK); // Only keep message bit
    bool obfuscationLevel = (int)((*seqNumBitField & OBFUSCATION_LEVEL_MASK) >> OBFUSCATION_LEVEL_OFFSET);
    sequenceNumber = (uint32_t)(*seqNumBitField & SEQUENCE_NUMBER_MASK ); // Remove the bit field

    //qDebug() << isReliable << isPartOfMessage << obfuscationLevel << sequenceNumber;

    if (isPartOfMessage) {
        uint32_t* messageNumberAndBitField = seqNumBitField + 1;

        uint32_t messageNumber = *messageNumberAndBitField & MESSAGE_NUMBER_MASK;
        short packetPosition = static_cast<short>(*messageNumberAndBitField >> PACKET_POSITION_OFFSET);

        uint32_t* messagePartNumber = messageNumberAndBitField + 1;

        //qDebug() << messageNumber << (int) packetPosition << messagePartNumber;
    }

    adjustPayloadStartAndCapacity(Packet::headerSize(isPartOfMessage), payloadSize > 0);

    /*if (getObfuscationLevel() != Packet::NoObfuscation) {
        obfuscate(NoObfuscation); // Undo obfuscation
    }*/

    auto headerOffset = Packet::headerSize(isPartOfMessage);
    type = *reinterpret_cast<const PacketType*>(packet.get() + headerOffset);

    version = *reinterpret_cast<const PacketVersion*>(packet.get() + headerOffset + sizeof(PacketType));
    quint16 local_id =  *reinterpret_cast<const PacketVersion*>(packet.get() + headerOffset + sizeof(PacketType));

    adjustPayloadStartAndCapacity(Packet::localHeaderSize(type), payloadSize > 0);

    //int h = (Packet::localHeaderSize(type) + Packet::headerSize(isPartOfMessage));
    //qDebug() << h << (quint8)type << (int)version << local_id;
}

int Packet::headerSize(bool isPartOfMessage) {
    return sizeof(uint32_t) +
            (isPartOfMessage ? 2*sizeof(uint32_t) : 0);
}

int Packet::localHeaderSize(PacketType type) {
    bool nonSourced = PacketTypeEnum::getNonSourcedPackets().contains(type);
    bool nonVerified = PacketTypeEnum::getNonVerifiedPackets().contains(type);
    qint64 optionalSize = (nonSourced ? 0 : 2) + ((nonSourced || nonVerified) ? 0 : 16);
    return sizeof(PacketType) + sizeof(PacketVersion) + optionalSize;
}

std::unique_ptr<Packet> Packet::create(uint32_t sequence, PacketType t, qint64 size)
{
    auto packet = std::unique_ptr<Packet>(new Packet(sequence,t,headerSize(false) + localHeaderSize(t) + size));

    packet->open(QIODevice::ReadWrite);

    return packet;
}

std::unique_ptr<Packet> Packet::fromReceivedPacket(char * data, qint64 size, QHostAddress addr, quint16 port)
{
    // allocate memory
    auto packet = std::unique_ptr<Packet>(new Packet(data, size, addr, port));

    packet->open(QIODevice::ReadOnly);

    return packet;
}


void Packet::adjustPayloadStartAndCapacity(int headerSize, bool shouldDecreasePayloadSize)
{
    payloadStart += headerSize;
    payloadCapacity -= headerSize;

    if (shouldDecreasePayloadSize) {
        payloadSize -= headerSize;
    }
}

bool Packet::reset() {
    if (isWritable()) {
        payloadSize = 0;
    }

    return QIODevice::reset();
}

qint64 Packet::writeData(const char* data, qint64 maxSize) {
    Q_ASSERT_X(maxSize <= bytesAvailableForWrite(), "BasePacket::writeData", "not enough space for write");

    // make sure we have the space required to write this block
    if (maxSize <= bytesAvailableForWrite()) {
        qint64 currentPos = pos();

        // good to go - write the data
        memcpy(payloadStart + currentPos, data, maxSize);

        // keep track of _payloadSize so we can just write the actual data when packet is about to be sent
        payloadSize = std::max(currentPos + maxSize, payloadSize);

        // return the number of bytes written
        return maxSize;
    } else {
        // not enough space left for this write - return an error
        return 0;
    }
}

qint64 Packet::readData(char* dest, qint64 maxSize) {
    // we're either reading what is left from the current position or what was asked to be read
    qint64 numBytesToRead = std::min(bytesLeftToRead(), maxSize);

    if (numBytesToRead > 0) {
        int currentPosition = pos();

        // read out the data
        memcpy(dest, payloadStart + currentPosition, numBytesToRead);
    }

    return numBytesToRead;
}

QByteArray Packet::readWithoutCopy(qint64 maxSize) {
    qint64 sizeToRead = std::min(size() - pos(), maxSize);
    QByteArray data { QByteArray::fromRawData(payloadStart + pos(), sizeToRead) };
    seek(pos() + sizeToRead);
    return data;
}
