#ifndef HMACAUTH_H
#define HMACAUTH_H

#include <vector>
#include <memory>
#include <QDebug>
#include <QObject>
#include <QtCore/QMutex>

#include <openssl/opensslv.h>
#include <openssl/hmac.h>

#include <QUuid>
#include <cassert>

class HMACAuth {
public:
    enum AuthMethod { MD5, SHA1, SHA224, SHA256, RIPEMD160 };
    using HMACHash = std::vector<unsigned char>;

    explicit HMACAuth(AuthMethod auth_method = MD5);
    ~HMACAuth();

    bool SetKey(const char* keyValue, int keyLen);
    bool SetKey(const QUuid& uidKey);
    // Calculate complete hash in one.
    bool CalculateHash(HMACHash& hashResult, const char* data, int dataLen);

    // Append to data to be hashed.
    bool AddData(const char* data, int dataLen);
    // Get the resulting hash from calls to addData().
    // Note that only one hash may be calculated at a time for each
    // HMACAuth instance if this interface is used.
    HMACHash Result();

private:
    QMutex _lock { QMutex::Recursive };
    struct hmac_ctx_st* hmac_context;
    AuthMethod auth_method;
};

#endif // HMACAUTH_H
