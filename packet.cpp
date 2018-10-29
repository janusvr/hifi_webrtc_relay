#include "packet.h"

PacketVersion VersionForPacketType(PacketType packetType) {
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
            return static_cast<PacketVersion>(EntityVersion::FixedLightSerialization);
        case PacketType::EntityQuery:
            return static_cast<PacketVersion>(EntityQueryPacketVersion::ConicalFrustums);
        case PacketType::AvatarIdentity:
        case PacketType::AvatarData:
        case PacketType::BulkAvatarData:
        case PacketType::KillAvatar:
            return static_cast<PacketVersion>(AvatarMixerPacketVersion::FarGrabJointsRedux);
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

Packet::Packet(uint32_t sequence, PacketType t, qint64 size, bool reliable, bool part_of_message)
{
    type = t;
    version = VersionForPacketType(t);

    packet_size = (size == -1) ? MAX_PACKET_SIZE: size;
    payload_size = 0;
    payload_capacity = packet_size;
    packet.reset(new char[packet_size]());
    payload_start = packet.get();
    sequence_number = sequence;
    is_reliable = reliable;
    is_part_of_message = part_of_message;

    // Pack the sequence number
    uint32_t *seq_num_bit_field = &sequence_number;
    if (is_reliable) {
        *seq_num_bit_field |= RELIABILITY_BIT_MASK;
    }
    if (is_part_of_message) {
        *seq_num_bit_field |= MESSAGE_BIT_MASK;
    }

    memcpy(packet.get(), seq_num_bit_field, sizeof(uint32_t));

    // Pack the packet type
    memcpy(packet.get() + sizeof(uint32_t), &type, sizeof(PacketType));

    // Pack the packet version
    memcpy(packet.get() + sizeof(uint32_t) + sizeof(PacketType), &version, sizeof(PacketVersion));

    AdjustPayloadStartAndCapacity(Packet::HeaderSize(false) + Packet::LocalHeaderSize(type));
}

Packet::Packet(char * data, qint64 size, QHostAddress addr, quint16 port)
{
    packet_size = size;

    packet.reset(new char[size]());
    memcpy(packet.get(),data,size);

    payload_start = packet.get();
    payload_capacity = size;
    payload_size = size;

    uint32_t* seq_num_bit_field = reinterpret_cast<uint32_t*>(packet.get());

    bool is_control = (bool) (*seq_num_bit_field & CONTROL_BIT_MASK); // Only keep reliability bit
    if (is_control)
    {
        AdjustPayloadStartAndCapacity(Packet::LocalControlHeaderSize(), payload_size > 0);
        ReadControlType();
        return;
    }

    is_reliable = (bool) (*seq_num_bit_field & RELIABILITY_BIT_MASK); // Only keep reliability bit
    is_part_of_message = (bool) (*seq_num_bit_field & MESSAGE_BIT_MASK); // Only keep message bit
    obfuscation_level = (int)((*seq_num_bit_field & OBFUSCATION_LEVEL_MASK) >> OBFUSCATION_LEVEL_OFFSET);
    sequence_number = (uint32_t)(*seq_num_bit_field & SEQUENCE_NUMBER_MASK ); // Remove the bit field

    //qDebug() << is_reliable << is_part_of_message << obfuscation_level << sequence_number;

    if (is_part_of_message) {
        //qDebug() << "part of message";
        uint32_t* message_number_and_bitfield = seq_num_bit_field + 1;

        message_number = *message_number_and_bitfield & MESSAGE_NUMBER_MASK;
        packet_position = static_cast<short>(*message_number_and_bitfield >> PACKET_POSITION_OFFSET);

        message_part_number = message_number_and_bitfield + 1;

        //qDebug() << message_number << (int) packet_position << message_part_number;
    }

    AdjustPayloadStartAndCapacity(Packet::HeaderSize(is_part_of_message), payload_size > 0);

    if (obfuscation_level != Packet::NoObfuscation) {
        //qDebug() << "unobfuscating";
        Obfuscate(Packet::NoObfuscation); // Undo obfuscation
    }

    auto header_offset = Packet::HeaderSize(is_part_of_message);
    type = *reinterpret_cast<const PacketType*>(packet.get() + header_offset);

    version = *reinterpret_cast<const PacketVersion*>(packet.get() + header_offset + sizeof(PacketType));
    quint16 local_id =  *reinterpret_cast<const PacketVersion*>(packet.get() + header_offset + sizeof(PacketType));

    AdjustPayloadStartAndCapacity(Packet::LocalHeaderSize(type), payload_size > 0);

    //int h = (Packet::LocalHeaderSize(type) + Packet::HeaderSize(is_part_of_message));
}

int Packet::HeaderSize(bool is_part_of_message) {
    return sizeof(uint32_t) +
            (is_part_of_message ? 2*sizeof(uint32_t) : 0);
}

int Packet::LocalHeaderSize(PacketType type) {
    bool non_sourced = PacketTypeEnum::GetNonSourcedPackets().contains(type);
    bool non_verified = PacketTypeEnum::GetNonVerifiedPackets().contains(type);
    qint64 optional_size = (non_sourced ? 0 : 2) + ((non_sourced || non_verified) ? 0 : 16);
    return sizeof(PacketType) + sizeof(PacketVersion) + optional_size;
}

int Packet::TotalHeaderSize() {
    return HeaderSize(is_part_of_message) + LocalHeaderSize(type);
}

std::unique_ptr<Packet> Packet::Create(uint32_t sequence, PacketType t, qint64 size)
{
    auto packet = std::unique_ptr<Packet>(new Packet(sequence,t,(size == -1) ? -1 : (HeaderSize(false) + LocalHeaderSize(t) + size)));

    packet->open(QIODevice::ReadWrite);

    return packet;
}

std::unique_ptr<Packet> Packet::FromReceivedPacket(char * data, qint64 size, QHostAddress addr, quint16 port)
{
    // allocate memory
    auto packet = std::unique_ptr<Packet>(new Packet(data, size, addr, port));

    packet->open(QIODevice::ReadOnly);

    return packet;
}


void Packet::AdjustPayloadStartAndCapacity(int header_size, bool should_decrease_payload_size)
{
    payload_start += header_size;
    payload_capacity -= header_size;

    if (should_decrease_payload_size) {
        payload_size -= header_size;
    }
}

bool Packet::reset() {
    if (isWritable()) {
        payload_size = 0;
    }

    return QIODevice::reset();
}

qint64 Packet::writeData(const char* data, qint64 max_size) {
    Q_ASSERT_X(max_size <= BytesAvailableForWrite(), "BasePacket::writeData", "not enough space for write");

    // make sure we have the space required to write this block
    if (max_size <= BytesAvailableForWrite()) {
        qint64 currentPos = pos();

        // good to go - write the data
        memcpy(payload_start + currentPos, data, max_size);

        // keep track of _payload_size so we can just write the actual data when packet is about to be sent
        payload_size = std::max(currentPos + max_size, payload_size);

        // return the number of bytes written
        return max_size;
    } else {
        // not enough space left for this write - return an error
        return 0;
    }
}

qint64 Packet::readData(char* dest, qint64 max_size) {
    // we're either reading what is left from the current position or what was asked to be read
    qint64 num_bytes_to_read = std::min(BytesLeftToRead(), max_size);

    if (num_bytes_to_read > 0) {
        int currentPosition = pos();

        // read out the data
        memcpy(dest, payload_start + currentPosition, num_bytes_to_read);
    }

    return num_bytes_to_read;
}

void Packet::Obfuscate(ObfuscationLevel level) {
    QList<uint64_t> KEYS = QList<uint64_t>() << 0x0 << 0x6362726973736574 << 0x7362697261726461 << 0x72687566666d616e;
    auto obfuscation_key = KEYS[obfuscation_level] ^ KEYS[level]; // Undo old and apply new one.
    if (obfuscation_key != 0) {

        int size = GetDataSize() - HeaderSize(is_part_of_message);
        char * current = GetData() + HeaderSize(is_part_of_message);
        auto xor_value = reinterpret_cast<const char*>(&obfuscation_key);

        for (int i = 0; i < size; ++i) {
            *(current++) ^= *(xor_value + (i % sizeof(uint64_t)));
        }

        // Update members and header
        obfuscation_level = level;

        uint32_t* seq_num_bit_field = reinterpret_cast<uint32_t*>(packet.get());

        // Write sequence number and reset bit field
        *seq_num_bit_field = (sequence_number);

        if (is_reliable) {
            *seq_num_bit_field |= RELIABILITY_BIT_MASK;
        }

        if (obfuscation_level != NoObfuscation) {
            *seq_num_bit_field |= (obfuscation_level << OBFUSCATION_LEVEL_OFFSET);
        }

        if (is_part_of_message) {
            *seq_num_bit_field |= MESSAGE_BIT_MASK;

            uint32_t* message_number_and_bitfield = seq_num_bit_field + 1;
            *message_number_and_bitfield = message_number;
            *message_number_and_bitfield |= packet_position << PACKET_POSITION_OFFSET;

            uint32_t* message_part_number = message_number_and_bitfield + 1;
            *this->message_part_number = *message_part_number;
        }
    }
}

void Packet::WriteSourceID(quint16 s)
{
    if (PacketTypeEnum::GetNonSourcedPackets().contains(type)) return;

    auto offset = Packet::HeaderSize(false) + sizeof(PacketType) + sizeof(PacketVersion);

    memcpy(packet.get() + offset, &s, sizeof(s));

    source_id = s;
    //qDebug() << "source id"  << source_id;
}

QByteArray Packet::HashForPacketAndHMAC(const Packet& packet, HMACAuth * hash) {
    int offset = Packet::HeaderSize(packet.GetIsPartOfMessage()) + sizeof(PacketType) + sizeof(PacketVersion)
        + 2 + 16;

    // add the packet payload and the connection UUID
    HMACAuth::HMACHash hash_result;
    if (!hash->CalculateHash(hash_result, packet.GetData() + offset, packet.GetDataSize() - offset)) {
        return QByteArray();
    }
    return QByteArray((const char*) hash_result.data(), (int) hash_result.size());
}

void Packet::WriteVerificationHash(HMACAuth * h)
{
    if (PacketTypeEnum::GetNonSourcedPackets().contains(type) || PacketTypeEnum::GetNonVerifiedPackets().contains(type))
        return;

    auto offset = Packet::HeaderSize(false) + sizeof(PacketType) + sizeof(PacketVersion)
                + 2; // Num bytes of localID

    QByteArray verification_hash = HashForPacketAndHMAC(*this, h);

    //qDebug() << "verification hash" << verificationHash << verificationHash.size();

    memcpy(packet.get() + offset, verification_hash.data(), verification_hash.size());
}

qint64 Packet::WriteString(const QString& string)
{
    QByteArray data = string.toUtf8();
    uint32_t length = data.length();
    write(reinterpret_cast<const char*>(&length), sizeof(length));
    write(data.constData(), data.length());
    return length + sizeof(uint32_t);
}

QString Packet::ReadString()
{
    uint32_t size;
    read(reinterpret_cast<char*>(&size), sizeof(uint32_t));
    auto string = QString::fromUtf8(payload_start + pos(), size);
    seek(pos() + size);
    return string;
}
