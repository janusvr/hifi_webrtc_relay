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
const int HIFI_INITIAL_UPDATE_INTERVAL_MSEC = 250;
const int HIFI_PING_UPDATE_INTERVAL_MSEC = 25;
const int HIFI_NUM_INITIAL_REQUESTS_BEFORE_FAIL = 10;
const int NUM_BYTES_RFC4122_UUID = 16;

class Utils
{
public:
    Utils();
    ~Utils();

    static void SetupTimestamp();
    static void SetupProtocolVersionSignatures();
    static QByteArray GetProtocolVersionSignature();
    static QString GetProtocolVersionSignatureBase64();
    static QUuid GetMachineFingerprint();
    static QString GetHardwareAddress(QHostAddress local_addr);
    static quint64 GetTimestamp();

private:
    static QString getMachineFingerprintString();

    static QByteArray protocolVersionSignature;
    static QString protocolVersionSignatureBase64;
    static QUuid machineFingerprint;

    static quint64 TIMESTAMP_REF;
    static QElapsedTimer timestampTimer;
};

#endif // UTILS_H
