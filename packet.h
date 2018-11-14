#ifndef PACKET_H
#define PACKET_H

#include <QObject>
#include <QHostInfo>
#include <QDebug>
#include <QUuid>

#include "hmacauth.h"

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

        ProxiedICEPing,
        ProxiedICEPingReply,
        ProxiedDomainListRequest,

        NUM_PACKET_TYPE
    };

    const static QHash<PacketTypeEnum::Value, PacketTypeEnum::Value> GetReplicatedPacketMapping() {
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

    const static QSet<PacketTypeEnum::Value> GetProxiedPackets() {
        const static QSet<PacketTypeEnum::Value> PROXIED_PACKETS = QSet<PacketTypeEnum::Value>()
            << PacketTypeEnum::Value::ProxiedICEPing
            << PacketTypeEnum::Value::ProxiedICEPingReply
            << PacketTypeEnum::Value::ProxiedDomainListRequest;
        return PROXIED_PACKETS;
    }

    const static QSet<PacketTypeEnum::Value> GetNonVerifiedPackets() {
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

    const static QSet<PacketTypeEnum::Value> GetNonSourcedPackets() {
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

    const static QSet<PacketTypeEnum::Value> GetDomainSourcedPackets() {
        const static QSet<PacketTypeEnum::Value> DOMAIN_SOURCED_PACKETS = QSet<PacketTypeEnum::Value>()
            << PacketTypeEnum::Value::AssetMappingOperation
            << PacketTypeEnum::Value::AssetGet
            << PacketTypeEnum::Value::AssetUpload;
        return DOMAIN_SOURCED_PACKETS;
    }

    const static QSet<PacketTypeEnum::Value> GetDomainIgnoredVerificationPackets() {
        const static QSet<PacketTypeEnum::Value> DOMAIN_IGNORED_VERIFICATION_PACKETS = QSet<PacketTypeEnum::Value>()
            << PacketTypeEnum::Value::AssetMappingOperationReply
            << PacketTypeEnum::Value::AssetGetReply
            << PacketTypeEnum::Value::AssetUploadReply;
        return DOMAIN_IGNORED_VERIFICATION_PACKETS;
    }
};

using PacketType = PacketTypeEnum::Value;
typedef char PacketVersion;

PacketVersion VersionForPacketType(PacketType packetType);
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
    BloomEffect,
    GrabProperties,
    ScriptGlmVectors,
    FixedLightSerialization
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
    MigrateAvatarEntitiesToTraits,
    FarGrabJointsRedux
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

using ControlBitAndType = uint32_t;

enum ControlType : uint16_t {
    ACK,
    Handshake,
    HandshakeACK,
    HandshakeRequest
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

    Packet(uint32_t sequence, PacketType t, qint64 size = MAX_PACKET_SIZE, bool reliable = false, bool part_of_message = false);
    Packet(uint32_t sequence, ControlType t, qint64 size = MAX_PACKET_SIZE);
    Packet(char * data, qint64 size);

    static int HeaderSize(bool is_part_of_message);
    static int LocalHeaderSize(PacketType type);
    static int LocalControlHeaderSize();
    int TotalHeaderSize();

    static std::unique_ptr<Packet> Create(uint32_t sequence, PacketType t, qint64 size = -1);
    static std::unique_ptr<Packet> FromReceivedPacket(char * data, qint64 size);

    static std::unique_ptr<Packet> CreateControl(uint32_t sequence, ControlType t, qint64 size = -1);
    static std::unique_ptr<Packet> FromReceivedControlPacket(char * data, qint64 size);

    void Obfuscate(ObfuscationLevel level);

    void WriteControlType();
    void ReadControlType();

    void WriteSourceID(quint16 s);
    void WriteVerificationHash(HMACAuth * h);

    void AdjustPayloadStartAndCapacity(int header_size, bool should_decrease_payload_size = false);

    qint64 BytesLeftToRead() const { return payload_size - pos();}
    qint64 BytesAvailableForWrite() const { return payload_capacity - pos();}

    bool reset();
    qint64 writeData(const char* data, qint64 max_size);
    qint64 readData(char* dest, qint64 max_size);

    qint64 WriteString(const QString& string);
    QString ReadString();

    char* GetData() { return packet.get(); }
    const char* GetData() const { return packet.get(); }
    qint64 GetDataSize() const { return (payload_start - packet.get()) + payload_size; }

    PacketType GetType() {return type;}
    ControlType GetControlType() {return control_type;}
    bool GetIsReliable() const {return is_reliable;}
    bool GetIsPartOfMessage() const {return is_part_of_message;}
    uint32_t GetSequenceNumber() {return sequence_number;}

    static QByteArray HashForPacketAndHMAC(const Packet& packet, HMACAuth * hash);

private:
    PacketType type;
    ControlType control_type;
    PacketVersion version;

    qint64 packet_size;
    qint64 payload_size;
    char * payload_start;
    qint64 payload_capacity;

    uint32_t obfuscation_level;
    bool is_part_of_message;
    bool is_reliable;
    uint32_t message_number;
    short packet_position;
    uint32_t * message_part_number;
    uint32_t sequence_number;

    quint16 source_id;

    std::unique_ptr<char[]> packet;
};

#endif // PACKET_H
