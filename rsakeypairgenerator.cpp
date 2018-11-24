#include "rsakeypairgenerator.h"

#ifdef __clang__
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

RSAKeypairGenerator::RSAKeypairGenerator(QObject* parent) :
    QObject(parent)
{

}

bool RSAKeypairGenerator::GenerateKeypair() {
    RSA* key_pair = RSA_new();
    BIGNUM* exponent = BN_new();

    const unsigned long RSA_KEY_EXPONENT = 65537;
    BN_set_word(exponent, RSA_KEY_EXPONENT);

    // seed the random number generator before we call RSA_generate_key_ex
    srand(time(NULL));

    const int RSA_KEY_BITS = 2048;

    if (!RSA_generate_key_ex(key_pair, RSA_KEY_BITS, exponent, NULL)) {
        qDebug() << "Error generating 2048-bit RSA Keypair -" << ERR_get_error();

        // we're going to bust out of here but first we cleanup the BIGNUM
        BN_free(exponent);
        return false;
    }

    // we don't need the BIGNUM anymore so clean that up
    BN_free(exponent);

    // grab the public key and private key from the file
    unsigned char* public_key_DER = NULL;
    int public_key_length = i2d_RSAPublicKey(key_pair, &public_key_DER);

    unsigned char* private_key_DER = NULL;
    int private_key_length = i2d_RSAPrivateKey(key_pair, &private_key_DER);

    if (public_key_length <= 0 || private_key_length <= 0) {
        qDebug() << "Error getting DER public or private key from RSA struct -" << ERR_get_error();

        // cleanup the RSA struct
        RSA_free(key_pair);

        // cleanup the public and private key DER data, if required
        if (public_key_length > 0) {
            OPENSSL_free(public_key_DER);
        }

        if (private_key_length > 0) {
            OPENSSL_free(private_key_DER);
        }

        return false;
    }

    // we have the public key and private key in memory
    // we can cleanup the RSA struct before we continue on
    RSA_free(key_pair);

    public_key = QByteArray { reinterpret_cast<char*>(public_key_DER), public_key_length };
    private_key = QByteArray { reinterpret_cast<char*>(private_key_DER), private_key_length };

    // cleanup the public_key_DER and public_key_DER data
    OPENSSL_free(public_key_DER);
    OPENSSL_free(private_key_DER);

    return true;
}
