#include "utils.h"

#ifdef Q_OS_WIN
#include <Windows.h>
#include <winreg.h>
#endif //Q_OS_WIN

#ifdef Q_OS_MAC
#include <IOKit/IOBSD.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/storage/IOMedia.h>
#endif //Q_OS_MAC

QByteArray Utils::protocolVersionSignature = QByteArray();
QString Utils::protocolVersionSignatureBase64 = QString();
QUuid Utils::machineFingerprint = QUuid();
quint64 Utils::TIMESTAMP_REF = 0;
QElapsedTimer Utils::timestampTimer = QElapsedTimer();

Utils::Utils()
{

}

Utils::~Utils()
{

}

void Utils::SetupTimestamp()
{
    TIMESTAMP_REF = QDateTime::currentMSecsSinceEpoch() * 1000;
    timestampTimer.start();
}

quint64 Utils::GetTimestamp()
{
    quint64 now;
    quint64 nsecsElapsed = timestampTimer.nsecsElapsed();
    quint64 usecsElapsed = nsecsElapsed / 1000;  // nsec to usec

    quint64 msecsCurrentTime = QDateTime::currentMSecsSinceEpoch();
    quint64 msecsEstimate = (TIMESTAMP_REF + usecsElapsed) / 1000; // usecs to msecs
    int possibleSkew = msecsEstimate - msecsCurrentTime;
    const int TOLERANCE = 10 * 1000; // up to 10 seconds of skew is tolerated
    if (abs(possibleSkew) > TOLERANCE) {
        // reset our TIME_REFERENCE and timer
        TIMESTAMP_REF = QDateTime::currentMSecsSinceEpoch() * 1000; // ms to usec
        timestampTimer.restart();
        now = TIMESTAMP_REF;
    } else {
        now = TIMESTAMP_REF + usecsElapsed;
    }

    return now;
}

void Utils::SetupProtocolVersionSignatures()
{
    QByteArray buffer;
    QDataStream stream(&buffer, QIODevice::WriteOnly);
    uint8_t numberOfProtocols = static_cast<uint8_t>(PacketType::NUM_PACKET_TYPE);
    stream << numberOfProtocols;
    for (uint8_t packetType = 0; packetType < numberOfProtocols; packetType++) {
        uint8_t packetTypeVersion = static_cast<uint8_t>(versionForPacketType(static_cast<PacketType>(packetType)));
        stream << packetTypeVersion;
    }
    QCryptographicHash hash(QCryptographicHash::Md5);
    hash.addData(buffer);
    protocolVersionSignature = hash.result();
    protocolVersionSignatureBase64 = protocolVersionSignature.toBase64();

    qDebug() << "Utils::SetupProtocolVersionSignatures - Completed";
}

QByteArray Utils::GetProtocolVersionSignature()
{
    return protocolVersionSignature;
}

QString Utils::GetProtocolVersionSignatureBase64()
{
    return protocolVersionSignatureBase64;
}

QUuid Utils::GetMachineFingerprint()
{
    if (machineFingerprint.isNull()) {
        QString uuidString = getMachineFingerprintString();

        // now, turn into uuid.  A malformed string will
        // return QUuid() ("{00000...}"), which handles
        // any errors in getting the string
        QUuid uuid(uuidString);

        //TODO: save out UUID to a settings file and use it
        if (uuid == QUuid()) {
            // no fallback yet, set one
            uuid = QUuid::createUuid();
        }

        machineFingerprint = uuid;
        //qDebug() << "Utils::GetMachineFingerprint - " << machineFingerprint;
    }

    return machineFingerprint;
}

QString Utils::getMachineFingerprintString() {
    QString uuidString;
#ifdef Q_OS_LINUX
    // sadly need to be root to get smbios guid from linux, so
    // for now lets do nothing.
#endif //Q_OS_LINUX

#ifdef Q_OS_MAC
    io_registry_entry_t ioRegistryRoot = IORegistryEntryFromPath(kIOMasterPortDefault, "IOService:/");
    CFStringRef uuidCf = (CFStringRef) IORegistryEntryCreateCFProperty(ioRegistryRoot, CFSTR(kIOPlatformUUIDKey), kCFAllocatorDefault, 0);
    IOObjectRelease(ioRegistryRoot);
    uuidString = QString::fromCFString(uuidCf);
    CFRelease(uuidCf);
    //qDebug() << "Utils::getMachineFingerprintString() - Mac serial number: " << uuidString;
#endif //Q_OS_MAC

#ifdef Q_OS_WIN
    HKEY cryptoKey;

    // try and open the key that contains the machine GUID
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &cryptoKey) == ERROR_SUCCESS) {
        DWORD type;
        DWORD guidSize;

        const char* MACHINE_GUID_KEY = "MachineGuid";

        // try and retrieve the size of the GUID value
        if (RegQueryValueEx(cryptoKey, MACHINE_GUID_KEY, NULL, &type, NULL, &guidSize) == ERROR_SUCCESS) {
            // make sure that the value is a string
            if (type == REG_SZ) {
                // retrieve the machine GUID and return that as our UUID string
                std::string machineGUID(guidSize / sizeof(char), '\0');

                if (RegQueryValueEx(cryptoKey, MACHINE_GUID_KEY, NULL, NULL,
                                    reinterpret_cast<LPBYTE>(&machineGUID[0]), &guidSize) == ERROR_SUCCESS) {
                    uuidString = QString::fromStdString(machineGUID);
                }
            }
        }

        RegCloseKey(cryptoKey);
    }

#endif //Q_OS_WIN

    return uuidString;

}

QString Utils::GetHardwareAddress(QHostAddress local_addr)
{
    // if possible, include the MAC address for the current interface in our connect request
    QString hardwareAddress;

    for (auto networkInterface : QNetworkInterface::allInterfaces()) {
        for (auto interfaceAddress : networkInterface.addressEntries()) {
            if (interfaceAddress.ip() == local_addr) {
                // this is the interface whose local IP matches what we've detected the current IP to be
                hardwareAddress = networkInterface.hardwareAddress();

                // stop checking interfaces and addresses
                break;
            }
        }

        // stop looping if this was the current interface
        if (!hardwareAddress.isEmpty()) {
            break;
        }
    }

    return hardwareAddress;
}
