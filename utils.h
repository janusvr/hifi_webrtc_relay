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
    static void SetupProtocolVersionSignature();
    static QByteArray GetProtocolVersionSignature();
    static QString GetProtocolVersionSignatureBase64();
    static QUuid GetMachineFingerprint();
    static QString GetHardwareAddress(QHostAddress local_addr);
    static quint64 GetTimestamp();

    static QString GetDomainName() {return domain_name;}
    static void SetDomainName(QString s) {domain_name = s;}
    static QString GetDomainPlaceName() {return domain_place_name;}
    static void SetDomainPlaceName(QString s) {domain_place_name = s;}
    static QUuid GetDomainID() {return domain_id;}
    static void SetDomainID(QUuid id) {domain_id = id;}
    static bool GetFinishedDomainIDRequest() {return finished_domain_id_request;}
    static void SetFinishedDomainIDRequest(bool b) {finished_domain_id_request = b;}

    static QString GetStunServerHostname() {return stun_server_hostname;}
    static void SetStunServerHostname(QString h) {stun_server_hostname = h;}
    static quint16 GetStunServerPort() {return stun_server_port;}
    static void SetStunServerPort(quint16 p) {stun_server_port = p;}

    static bool GetUseCustomIceServer() {return use_custom_ice_server;}
    static void SetUseCustomIceServer(bool b) {use_custom_ice_server = b;}
    static QString GetIceServerHostname() {return ice_server_hostname;}
    static void SetIceServerHostname(QString h) {ice_server_hostname = h;}
    static QHostAddress GetIceServerAddress() {return ice_server_address;}
    static void SetIceServerAddress(QHostAddress h) {ice_server_address = h;}
    static quint16 GetIceServerPort() {return ice_server_port;}
    static void SetIceServerPort(quint16 p) {ice_server_port = p;}

private:
    static QString GetMachineFingerprintString();

    static QByteArray protocol_version_signature;
    static QString protocol_version_signature_base64;
    static QUuid machine_fingerprint;

    static quint64 TIMESTAMP_REF;
    static QElapsedTimer timestamp_timer;

    static bool finished_domain_id_request;
    static QString domain_name;
    static QString domain_place_name;
    static QUuid domain_id;

    static QString stun_server_hostname;
    static quint16 stun_server_port;

    static bool use_custom_ice_server;
    static QString ice_server_hostname;
    static QHostAddress ice_server_address;
    static quint16 ice_server_port;
};

#endif // UTILS_H
