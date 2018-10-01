#include "hmacauth.h"

#if OPENSSL_VERSION_NUMBER >= 0x10100000
HMACAuth::HMACAuth(AuthMethod authMethod)
    : hmac_context(HMAC_CTX_new())
    , auth_method(authMethod) { }

HMACAuth::~HMACAuth()
{
    HMAC_CTX_free(hmac_context);
}

#else

HMACAuth::HMACAuth(AuthMethod auth_method)
    : hmac_context(new HMAC_CTX())
    , auth_method(auth_method) {
    HMAC_CTX_init(hmac_context);
}

HMACAuth::~HMACAuth() {
    HMAC_CTX_cleanup(hmac_context);
    delete hmac_context;
}
#endif

bool HMACAuth::SetKey(const char* keyValue, int keyLen) {
    const EVP_MD* ssl_struct = nullptr;

    switch (auth_method) {
    case MD5:
        ssl_struct = EVP_md5();
        break;

    case SHA1:
        ssl_struct = EVP_sha1();
        break;

    case SHA224:
        ssl_struct = EVP_sha224();
        break;

    case SHA256:
        ssl_struct = EVP_sha256();
        break;

    case RIPEMD160:
        ssl_struct = EVP_ripemd160();
        break;

    default:
        return false;
    }

    QMutexLocker lock(&_lock);
    return (bool) HMAC_Init_ex(hmac_context, keyValue, keyLen, ssl_struct, nullptr);
}

bool HMACAuth::SetKey(const QUuid& uidKey) {
    const QByteArray rfcBytes(uidKey.toRfc4122());
    return SetKey(rfcBytes.constData(), rfcBytes.length());
}

bool HMACAuth::AddData(const char* data, int data_len) {
    QMutexLocker lock(&_lock);
    return (bool) HMAC_Update(hmac_context, reinterpret_cast<const unsigned char*>(data), data_len);
}

HMACAuth::HMACHash HMACAuth::Result() {
    HMACHash hash_value(EVP_MAX_MD_SIZE);
    unsigned int hash_len;
    QMutexLocker lock(&_lock);

    auto hmac_result = HMAC_Final(hmac_context, &hash_value[0], &hash_len);

    if (hmac_result) {
        hash_value.resize((size_t)hash_len);
    } else {
        // the HMAC_FINAL call failed - should not be possible to get into this state
        qDebug() << "Error occured calling HMAC_Final";
    }

    // Clear state for possible reuse.
    HMAC_Init_ex(hmac_context, nullptr, 0, nullptr, nullptr);
    return hash_value;
}

bool HMACAuth::CalculateHash(HMACHash& hash_result, const char* data, int data_len) {
    QMutexLocker lock(&_lock);
    if (!AddData(data, data_len)) {
        qDebug() << "Error occured calling HMACAuth::addData()";
        return false;
    }

    hash_result = Result();
    return true;
}
