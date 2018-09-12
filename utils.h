#ifndef UTILS_H
#define UTILS_H

#include <QObject>
#include <QCryptographicHash>
#include <QDataStream>
#include <QtNetwork>

#include "packet.h"

class Utils
{
public:
    Utils();
    ~Utils();

    static void SetupProtocolVersionSignatures();
    static QByteArray GetProtocolVersionSignature();
    static QString GetProtocolVersionSignatureBase64();
    static QUuid GetMachineFingerprint();
    static QString GetHardwareAddress(QHostAddress local_addr);

private:
    static QString getMachineFingerprintString();

    static QByteArray protocolVersionSignature;
    static QString protocolVersionSignatureBase64;
    static QUuid machineFingerprint;
};

#endif // UTILS_H
