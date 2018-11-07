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

QByteArray Utils::protocol_version_signature = QByteArray();
QString Utils::protocol_version_signature_base64 = QString();
QUuid Utils::machine_fingerprint = QUuid();
quint64 Utils::TIMESTAMP_REF = 0;
QElapsedTimer Utils::timestamp_timer = QElapsedTimer();

QHostAddress Utils::default_ice_server_address = QHostAddress();
quint16 Utils::default_ice_server_port = 7337;

Utils::Utils()
{

}

Utils::~Utils()
{

}

QHostAddress Utils::GetDefaultIceServerAddress()
{
    return default_ice_server_address;
}

void Utils::SetDefaultIceServerAddress(QHostAddress a)
{
    default_ice_server_address = a;
}

quint16 Utils::GetDefaultIceServerPort()
{
    return default_ice_server_port;
}

void Utils::SetDefaultIceServerPort(quint16 p)
{
    default_ice_server_port = p;
}

void Utils::SetupTimestamp()
{
    TIMESTAMP_REF = QDateTime::currentMSecsSinceEpoch() * 1000;
    timestamp_timer.start();
}

quint64 Utils::GetTimestamp()
{
    quint64 now;
    quint64 nsecs_elapsed = timestamp_timer.nsecsElapsed();
    quint64 usecs_elapsed = nsecs_elapsed / 1000;  // nsec to usec

    quint64 msecs_current_time = QDateTime::currentMSecsSinceEpoch();
    quint64 msecs_estimate = (TIMESTAMP_REF + usecs_elapsed) / 1000; // usecs to msecs
    int possible_skew = msecs_estimate - msecs_current_time;
    const int TOLERANCE = 10 * 1000; // up to 10 seconds of skew is tolerated
    if (abs(possible_skew) > TOLERANCE) {
        // reset our TIME_REFERENCE and timer
        TIMESTAMP_REF = QDateTime::currentMSecsSinceEpoch() * 1000; // ms to usec
        timestamp_timer.restart();
        now = TIMESTAMP_REF;
    } else {
        now = TIMESTAMP_REF + usecs_elapsed;
    }

    return now;
}

void Utils::SetupProtocolVersionSignature()
{
    QByteArray buffer;
    QDataStream stream(&buffer, QIODevice::WriteOnly);
    uint8_t number_of_protocols = static_cast<uint8_t>(PacketType::NUM_PACKET_TYPE) - PacketTypeEnum::GetProxiedPackets().size();
    stream << number_of_protocols;
    for (uint8_t packet_type = 0; packet_type < static_cast<uint8_t>(PacketType::NUM_PACKET_TYPE); packet_type++) {
        if (!PacketTypeEnum::GetProxiedPackets().contains(static_cast<PacketType>(packet_type))) {
            uint8_t packet_type_version = static_cast<uint8_t>(VersionForPacketType(static_cast<PacketType>(packet_type)));
            stream << packet_type_version;
        }
    }
    QCryptographicHash hash(QCryptographicHash::Md5);
    hash.addData(buffer);
    protocol_version_signature = hash.result();
    protocol_version_signature_base64 = protocol_version_signature.toBase64();

    qDebug() << "Utils::SetupProtocolVersionSignature - Completed";
}

QByteArray Utils::GetProtocolVersionSignature()
{
    return protocol_version_signature;
}

QString Utils::GetProtocolVersionSignatureBase64()
{
    return protocol_version_signature_base64;
}

QUuid Utils::GetMachineFingerprint()
{
    if (machine_fingerprint.isNull()) {
        QString uuid_string = GetMachineFingerprintString();

        // now, turn into uuid.  A malformed string will
        // return QUuid() ("{00000...}"), which handles
        // any errors in getting the string
        QUuid uuid(uuid_string);

        //TODO: save out UUID to a settings file and use it
        if (uuid == QUuid()) {
            // no fallback yet, set one
            uuid = QUuid::createUuid();
        }

        machine_fingerprint = uuid;
        //qDebug() << "Utils::GetMachineFingerprint - " << machine_fingerprint;
    }

    return machine_fingerprint;
}

QString Utils::GetMachineFingerprintString() {
    QString uuid_string;
#ifdef Q_OS_LINUX
    // sadly need to be root to get smbios guid from linux, so
    // for now lets do nothing.
#endif //Q_OS_LINUX

#ifdef Q_OS_MAC
    io_registry_entry_t ioRegistryRoot = IORegistryEntryFromPath(kIOMasterPortDefault, "IOService:/");
    CFStringRef uuidCf = (CFStringRef) IORegistryEntryCreateCFProperty(ioRegistryRoot, CFSTR(kIOPlatformUUIDKey), kCFAllocatorDefault, 0);
    IOObjectRelease(ioRegistryRoot);
    uuid_string = QString::fromCFString(uuidCf);
    CFRelease(uuidCf);
    //qDebug() << "Utils::GetMachineFingerprintString() - Mac serial number: " << uuid_string;
#endif //Q_OS_MAC

#ifdef Q_OS_WIN
    HKEY cryptoKey;

    // try and open the key that contains the machine GUID
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &cryptoKey) == ERROR_SUCCESS) {
        DWORD type;
        DWORD guidSize;

        const LPCWSTR MACHINE_GUID_KEY = L"MachineGuid";

        // try and retrieve the size of the GUID value
        if (RegQueryValueEx(cryptoKey, MACHINE_GUID_KEY, NULL, &type, NULL, &guidSize) == ERROR_SUCCESS) {
            // make sure that the value is a string
            if (type == REG_SZ) {
                // retrieve the machine GUID and return that as our UUID string
                std::string machineGUID(guidSize / sizeof(char), '\0');

                if (RegQueryValueEx(cryptoKey, MACHINE_GUID_KEY, NULL, NULL,
                                    reinterpret_cast<LPBYTE>(&machineGUID[0]), &guidSize) == ERROR_SUCCESS) {
                    uuid_string = QString::fromStdString(machineGUID);
                }
            }
        }

        RegCloseKey(cryptoKey);
    }

#endif //Q_OS_WIN

    return uuid_string;

}

QString Utils::GetHardwareAddress(QHostAddress local_addr)
{
    // if possible, include the MAC address for the current interface in our connect request
    QString hardware_address;

    for (auto network_interface : QNetworkInterface::allInterfaces()) {
        for (auto interface_addresss : network_interface.addressEntries()) {
            if (interface_addresss.ip().toIPv4Address() == local_addr.toIPv4Address()) {
                // this is the interface whose local IP matches what we've detected the current IP to be
                hardware_address = network_interface.hardwareAddress();

                // stop checking interfaces and addresses
                break;
            }
        }

        // stop looping if this was the current interface
        if (!hardware_address.isEmpty()) {
            break;
        }
    }

    return hardware_address;
}
