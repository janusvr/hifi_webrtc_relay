#ifndef PACKET_H
#define PACKET_H

#include <QObject>
#include <QHostInfo>
#include <QDebug>
#include <QUuid>

class PacketTypeEnum {
public:
    // If adding a new packet packetType, you can replace one marked usable or add at the end.
    // This enum must hold 256 or fewer packet types (so the value is <= 255) since it is statically typed as a uint8_t
    enum class Value : uint8_t {
        Unknown,
        StunResponse,
        DomainList,
        Ping,
        PingReply,
        KillAvatar,
        AvatarData,
        InjectAudio,
        MixedAudio,
        MicrophoneAudioNoEcho,
        MicrophoneAudioWithEcho,
        BulkAvatarData,
        SilentAudioFrame,
        DomainListRequest,
        RequestAssignment,
        CreateAssignment,
        DomainConnectionDenied,
        MuteEnvironment,
        AudioStreamStats,
        DomainServerPathQuery,
        DomainServerPathResponse,
        DomainServerAddedNode,
        ICEServerPeerInformation,
        ICEServerQuery,
        OctreeStats,
        SetAvatarTraits,
        AvatarIdentityRequest,
        AssignmentClientStatus,
        NoisyMute,
        AvatarIdentity,
        NodeIgnoreRequest,
        DomainConnectRequest,
        DomainServerRequireDTLS,
        NodeJsonStats,
        OctreeDataNack,
        StopNode,
        AudioEnvironment,
        EntityEditNack,
        ICEServerHeartbeat,
        ICEPing,
        ICEPingReply,
        EntityData,
        EntityQuery,
        EntityAdd,
        EntityErase,
        EntityEdit,
        DomainServerConnectionToken,
        DomainSettingsRequest,
        DomainSettings,
        AssetGet,
        AssetGetReply,
        AssetUpload,
        AssetUploadReply,
        AssetGetInfo,
        AssetGetInfoReply,
        DomainDisconnectRequest,
        DomainServerRemovedNode,
        MessagesData,
        MessagesSubscribe,
        MessagesUnsubscribe,
        ICEServerHeartbeatDenied,
        AssetMappingOperation,
        AssetMappingOperationReply,
        ICEServerHeartbeatACK,
        NegotiateAudioFormat,
        SelectedAudioFormat,
        MoreEntityShapes,
        NodeKickRequest,
        NodeMuteRequest,
        RadiusIgnoreRequest,
        UsernameFromIDRequest,
        UsernameFromIDReply,
        AvatarQuery,
        RequestsDomainListData,
        PerAvatarGainSet,
        EntityScriptGetStatus,
        EntityScriptGetStatusReply,
        ReloadEntityServerScript,
        EntityPhysics,
        EntityServerScriptLog,
        AdjustAvatarSorting,
        OctreeFileReplacement,
        CollisionEventChanges,
        ReplicatedMicrophoneAudioNoEcho,
        ReplicatedMicrophoneAudioWithEcho,
        ReplicatedInjectAudio,
        ReplicatedSilentAudioFrame,
        ReplicatedAvatarIdentity,
        ReplicatedKillAvatar,
        ReplicatedBulkAvatarData,
        DomainContentReplacementFromUrl,
        ChallengeOwnership,
        EntityScriptCallMethod,
        ChallengeOwnershipRequest,
        ChallengeOwnershipReply,

        OctreeDataFileRequest,
        OctreeDataFileReply,
        OctreeDataPersist,

        EntityClone,
        EntityQueryInitialResultsComplete,
        BulkAvatarTraits,

        NUM_PACKET_TYPE
    };

    const static QHash<PacketTypeEnum::Value, PacketTypeEnum::Value> getReplicatedPacketMapping() {
        const static QHash<PacketTypeEnum::Value, PacketTypeEnum::Value> REPLICATED_PACKET_MAPPING {
            { PacketTypeEnum::Value::MicrophoneAudioNoEcho, PacketTypeEnum::Value::ReplicatedMicrophoneAudioNoEcho },
            { PacketTypeEnum::Value::MicrophoneAudioWithEcho, PacketTypeEnum::Value::ReplicatedMicrophoneAudioWithEcho },
            { PacketTypeEnum::Value::InjectAudio, PacketTypeEnum::Value::ReplicatedInjectAudio },
            { PacketTypeEnum::Value::SilentAudioFrame, PacketTypeEnum::Value::ReplicatedSilentAudioFrame },
            { PacketTypeEnum::Value::AvatarIdentity, PacketTypeEnum::Value::ReplicatedAvatarIdentity },
            { PacketTypeEnum::Value::KillAvatar, PacketTypeEnum::Value::ReplicatedKillAvatar },
            { PacketTypeEnum::Value::BulkAvatarData, PacketTypeEnum::Value::ReplicatedBulkAvatarData }
        };
        return REPLICATED_PACKET_MAPPING;
    }

    const static QSet<PacketTypeEnum::Value> getNonVerifiedPackets() {
        const static QSet<PacketTypeEnum::Value> NON_VERIFIED_PACKETS = QSet<PacketTypeEnum::Value>()
            << PacketTypeEnum::Value::NodeJsonStats
            << PacketTypeEnum::Value::EntityQuery
            << PacketTypeEnum::Value::OctreeDataNack
            << PacketTypeEnum::Value::EntityEditNack
            << PacketTypeEnum::Value::DomainListRequest
            << PacketTypeEnum::Value::StopNode
            << PacketTypeEnum::Value::DomainDisconnectRequest
            << PacketTypeEnum::Value::UsernameFromIDRequest
            << PacketTypeEnum::Value::NodeKickRequest
            << PacketTypeEnum::Value::NodeMuteRequest;
        return NON_VERIFIED_PACKETS;
    }

    const static QSet<PacketTypeEnum::Value> getNonSourcedPackets() {
        const static QSet<PacketTypeEnum::Value> NON_SOURCED_PACKETS = QSet<PacketTypeEnum::Value>()
            << PacketTypeEnum::Value::StunResponse << PacketTypeEnum::Value::CreateAssignment
            << PacketTypeEnum::Value::RequestAssignment << PacketTypeEnum::Value::DomainServerRequireDTLS
            << PacketTypeEnum::Value::DomainConnectRequest << PacketTypeEnum::Value::DomainList
            << PacketTypeEnum::Value::DomainConnectionDenied << PacketTypeEnum::Value::DomainServerPathQuery
            << PacketTypeEnum::Value::DomainServerPathResponse << PacketTypeEnum::Value::DomainServerAddedNode
            << PacketTypeEnum::Value::DomainServerConnectionToken << PacketTypeEnum::Value::DomainSettingsRequest
            << PacketTypeEnum::Value::OctreeDataFileRequest << PacketTypeEnum::Value::OctreeDataFileReply
            << PacketTypeEnum::Value::OctreeDataPersist << PacketTypeEnum::Value::DomainContentReplacementFromUrl
            << PacketTypeEnum::Value::DomainSettings << PacketTypeEnum::Value::ICEServerPeerInformation
            << PacketTypeEnum::Value::ICEServerQuery << PacketTypeEnum::Value::ICEServerHeartbeat
            << PacketTypeEnum::Value::ICEServerHeartbeatACK << PacketTypeEnum::Value::ICEPing
            << PacketTypeEnum::Value::ICEPingReply << PacketTypeEnum::Value::ICEServerHeartbeatDenied
            << PacketTypeEnum::Value::AssignmentClientStatus << PacketTypeEnum::Value::StopNode
            << PacketTypeEnum::Value::DomainServerRemovedNode << PacketTypeEnum::Value::UsernameFromIDReply
            << PacketTypeEnum::Value::OctreeFileReplacement << PacketTypeEnum::Value::ReplicatedMicrophoneAudioNoEcho
            << PacketTypeEnum::Value::ReplicatedMicrophoneAudioWithEcho << PacketTypeEnum::Value::ReplicatedInjectAudio
            << PacketTypeEnum::Value::ReplicatedSilentAudioFrame << PacketTypeEnum::Value::ReplicatedAvatarIdentity
            << PacketTypeEnum::Value::ReplicatedKillAvatar << PacketTypeEnum::Value::ReplicatedBulkAvatarData;
        return NON_SOURCED_PACKETS;
    }

    const static QSet<PacketTypeEnum::Value> getDomainSourcedPackets() {
        const static QSet<PacketTypeEnum::Value> DOMAIN_SOURCED_PACKETS = QSet<PacketTypeEnum::Value>()
            << PacketTypeEnum::Value::AssetMappingOperation
            << PacketTypeEnum::Value::AssetGet
            << PacketTypeEnum::Value::AssetUpload;
        return DOMAIN_SOURCED_PACKETS;
    }

    const static QSet<PacketTypeEnum::Value> getDomainIgnoredVerificationPackets() {
        const static QSet<PacketTypeEnum::Value> DOMAIN_IGNORED_VERIFICATION_PACKETS = QSet<PacketTypeEnum::Value>()
            << PacketTypeEnum::Value::AssetMappingOperationReply
            << PacketTypeEnum::Value::AssetGetReply
            << PacketTypeEnum::Value::AssetUploadReply;
        return DOMAIN_IGNORED_VERIFICATION_PACKETS;
    }
};

using PacketType = PacketTypeEnum::Value;
typedef char PacketVersion;

PacketVersion versionForPacketType(PacketType packetType);
uint qHash(const PacketType& key, uint seed);

// Due to the different legacy behaviour, we need special processing for domains that were created before
// the zone inheritance modes were added.  These have version numbers up to 80
enum class EntityVersion : PacketVersion {
    StrokeColorProperty = 0,
    HasDynamicOwnershipTests,
    HazeEffect,
    StaticCertJsonVersionOne,
    OwnershipChallengeFix,
    ZoneLightInheritModes = 82,
    ZoneStageRemoved,
    SoftEntities,
    MaterialEntities,
    ShadowControl,
    MaterialData,
    CloneableData,
    CollisionMask16Bytes,
    YieldSimulationOwnership,
    ParticleEntityFix,
    ParticleSpin,
    BloomEffect
};

enum class EntityScriptCallMethodVersion : PacketVersion {
    ServerCallable = 18,
    ClientCallable = 19
};

enum class EntityQueryPacketVersion: PacketVersion {
    JSONFilter = 18,
    JSONFilterWithFamilyTree = 19,
    ConnectionIdentifier = 20,
    RemovedJurisdictions = 21,
    MultiFrustumQuery = 22,
    ConicalFrustums = 23
};

enum class AssetServerPacketVersion: PacketVersion {
    VegasCongestionControl = 19,
    RangeRequestSupport,
    RedirectedMappings,
    BakingTextureMeta
};

enum class AvatarMixerPacketVersion : PacketVersion {
    TranslationSupport = 17,
    SoftAttachmentSupport,
    AvatarEntities,
    AbsoluteSixByteRotations,
    SensorToWorldMat,
    HandControllerJoints,
    HasKillAvatarReason,
    SessionDisplayName,
    Unignore,
    ImmediateSessionDisplayNameUpdates,
    VariableAvatarData,
    AvatarAsChildFixes,
    StickAndBallDefaultAvatar,
    IdentityPacketsIncludeUpdateTime,
    AvatarIdentitySequenceId,
    MannequinDefaultAvatar,
    AvatarIdentitySequenceFront,
    IsReplicatedInAvatarIdentity,
    AvatarIdentityLookAtSnapping,
    UpdatedMannequinDefaultAvatar,
    AvatarJointDefaultPoseFlags,
    FBXReaderNodeReparenting,
    FixMannequinDefaultAvatarFeet,
    ProceduralFaceMovementFlagsAndBlendshapes,
    FarGrabJoints,
    MigrateSkeletonURLToTraits,
    MigrateAvatarEntitiesToTraits
};

enum class DomainConnectRequestVersion : PacketVersion {
    NoHostname = 17,
    HasHostname,
    HasProtocolVersions,
    HasMACAddress,
    HasMachineFingerprint,
    AlwaysHasMachineFingerprint
};

enum class DomainConnectionDeniedVersion : PacketVersion {
    ReasonMessageOnly = 17,
    IncludesReasonCode,
    IncludesExtraInfo
};

enum class DomainServerAddedNodeVersion : PacketVersion {
    PrePermissionsGrid = 17,
    PermissionsGrid
};

enum class DomainListVersion : PacketVersion {
    PrePermissionsGrid = 18,
    PermissionsGrid,
    GetUsernameFromUUIDSupport,
    GetMachineFingerprintFromUUIDSupport,
    AuthenticationOptional
};

enum class AudioVersion : PacketVersion {
    HasCompressedAudio = 17,
    CodecNameInAudioPackets,
    Exactly10msAudioPackets,
    TerminatingStreamStats,
    SpaceBubbleChanges,
    HasPersonalMute,
    HighDynamicRangeVolume,
};

enum class MessageDataVersion : PacketVersion {
    TextOrBinaryData = 18
};

enum class IcePingVersion : PacketVersion {
    SendICEPeerID = 18
};

enum class PingVersion : PacketVersion {
    IncludeConnectionID = 18
};

enum class AvatarQueryVersion : PacketVersion {
    SendMultipleFrustums = 21,
    ConicalFrustums = 22
};

const int UDP_IPV4_HEADER_SIZE = 28;
const int MAX_PACKET_SIZE_WITH_UDP_HEADER = 1492;
const int MAX_PACKET_SIZE = MAX_PACKET_SIZE_WITH_UDP_HEADER - UDP_IPV4_HEADER_SIZE;
const int CONTROL_BIT_SIZE = 1;
const int RELIABILITY_BIT_SIZE = 1;
const int MESSAGE_BIT_SIZE = 1;
const int OBFUSCATION_LEVEL_SIZE = 2;
const int SEQUENCE_NUMBER_SIZE= 27;

const int PACKET_POSITION_SIZE = 2;
const int MESSAGE_NUMBER_SIZE = 30;

const int MESSAGE_PART_NUMBER_SIZE = 32;

const int SEQUENCE_NUMBER_OFFSET = 0;
const int OBFUSCATION_LEVEL_OFFSET = SEQUENCE_NUMBER_OFFSET + SEQUENCE_NUMBER_SIZE;
const int MESSAGE_BIT_OFFSET = OBFUSCATION_LEVEL_OFFSET + OBFUSCATION_LEVEL_SIZE;
const int RELIABILITY_BIT_OFFSET = MESSAGE_BIT_OFFSET + MESSAGE_BIT_SIZE;
const int CONTROL_BIT_OFFSET = RELIABILITY_BIT_OFFSET + RELIABILITY_BIT_SIZE;

const int MESSAGE_NUMBER_OFFSET = 0;
const int PACKET_POSITION_OFFSET = MESSAGE_NUMBER_OFFSET + MESSAGE_NUMBER_SIZE;

const int MESSAGE_PART_NUMBER_OFFSET = 0;

const uint32_t CONTROL_BIT_MASK = uint32_t(1) << CONTROL_BIT_OFFSET;
const uint32_t RELIABILITY_BIT_MASK = uint32_t(1) << RELIABILITY_BIT_OFFSET;
const uint32_t MESSAGE_BIT_MASK = uint32_t(1) << MESSAGE_BIT_OFFSET;
const uint32_t OBFUSCATION_LEVEL_MASK = uint32_t(3) << OBFUSCATION_LEVEL_OFFSET;
const uint32_t BIT_FIELD_MASK = CONTROL_BIT_MASK | RELIABILITY_BIT_MASK | MESSAGE_BIT_MASK | OBFUSCATION_LEVEL_MASK;
const uint32_t SEQUENCE_NUMBER_MASK = ~BIT_FIELD_MASK;

const uint32_t PACKET_POSITION_MASK = uint32_t(3) << PACKET_POSITION_OFFSET;
const uint32_t MESSAGE_NUMBER_MASK = ~PACKET_POSITION_MASK;

static const uint32_t MESSAGE_PART_NUMBER_MASK = ~uint32_t(0);

class Packet : public QIODevice
{
public:
    // Use same size as SequenceNumberAndBitField so we can use the enum with bitwise operations
    enum ObfuscationLevel : uint32_t {
        NoObfuscation = 0x0, // 00
        ObfuscationL1 = 0x1, // 01
        ObfuscationL2 = 0x2, // 10
        ObfuscationL3 = 0x3, // 11
    };

    Packet(uint32_t sequence, PacketType t, qint64 size = MAX_PACKET_SIZE);
    Packet(char * data, qint64 size, QHostAddress addr, quint16 port);

    static int headerSize(bool isPartOfMessage);
    static int localHeaderSize(PacketType type);
    int totalHeaderSize();

    static std::unique_ptr<Packet> create(uint32_t sequence, PacketType t, qint64 size = -1);
    static std::unique_ptr<Packet> fromReceivedPacket(char * data, qint64 size, QHostAddress addr, quint16 port);

    void obfuscate(ObfuscationLevel level);

    void adjustPayloadStartAndCapacity(int headerSize, bool shouldDecreasePayloadSize = false);

    qint64 bytesLeftToRead() const { return payloadSize - pos();}
    qint64 bytesAvailableForWrite() const { return payloadCapacity - pos();}

    bool reset();
    qint64 writeData(const char* data, qint64 maxSize);
    qint64 readData(char* dest, qint64 maxSize);
    QByteArray readWithoutCopy(qint64 maxSize);

    char* getData() { return packet.get(); }
    const char* getData() const { return packet.get(); }
    qint64 getDataSize() const { return (payloadStart - packet.get()) + payloadSize; }

    PacketType getType() {return type;}
    uint32_t getSequenceNumber() {return sequenceNumber;}

private:
    PacketType type;
    PacketVersion version;

    qint64 packetSize;
    qint64 payloadSize;
    char * payloadStart;
    qint64 payloadCapacity;

    uint32_t obfuscationLevel;
    bool isPartOfMessage;
    bool isReliable;
    uint32_t messageNumber;
    short packetPosition;
    uint32_t * messagePartNumber;
    uint32_t sequenceNumber;

    std::unique_ptr<char[]> packet;
};

#endif // PACKET_H
