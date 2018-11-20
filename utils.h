#ifndef UTILS_H
#define UTILS_H

#include <QObject>
#include <QCryptographicHash>
#include <QDataStream>
#include <QtNetwork>

#include "packet.h"

const uint32_t RFC_5389_MAGIC_COOKIE = 0x2112A442;
const int NUM_BYTES_STUN_HEADER = 20;

const quint16 DEFAULT_DOMAIN_SERVER_PORT = 40102;
const int HIFI_INITIAL_UPDATE_INTERVAL_MSEC = 500;
const int HIFI_PING_UPDATE_INTERVAL_MSEC = 1000;
const int HIFI_NUM_INITIAL_REQUESTS_BEFORE_FAIL = 10;
const int NUM_BYTES_RFC4122_UUID = 16;

const int HIFI_TIMEOUT_MSEC = 10000;

class Utils
{
public:
    Utils();
    ~Utils();

    static void SetupTimestamp();
    static void SetupProtocolVersionSignature();
    static QByteArray GetProtocolVersionSignature();
    static QString GetProtocolVersionSignatureBase64();
    static QUuid GetMachineFingerprint();
    static QString GetHardwareAddress(QHostAddress local_addr);
    static quint64 GetTimestamp();

    static QHostAddress GetDefaultIceServerAddress();
    static void SetDefaultIceServerAddress(QHostAddress a);
    static quint16 GetDefaultIceServerPort();
    static void SetDefaultIceServerPort(quint16 p);

private:
    static QString GetMachineFingerprintString();

    static QHostAddress default_ice_server_address;
    static quint16 default_ice_server_port;

    static QByteArray protocol_version_signature;
    static QString protocol_version_signature_base64;
    static QUuid machine_fingerprint;

    static quint64 TIMESTAMP_REF;
    static QElapsedTimer timestamp_timer;
};

#endif // UTILS_H
