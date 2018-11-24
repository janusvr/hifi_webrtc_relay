#ifndef RSAKEYPAIRGENERATOR_H
#define RSAKEYPAIRGENERATOR_H

#include <QtCore/QObject>
#include <QtCore/QRunnable>
#include <QtCore/QUuid>

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <QDebug>

class RSAKeypairGenerator : public QObject {
    Q_OBJECT
public:
    RSAKeypairGenerator(QObject* parent = nullptr);

    bool GenerateKeypair();
    QByteArray GetPublicKey() {return public_key;}
    QByteArray GetPrivateKey() {return private_key;}

private:
    QByteArray public_key;
    QByteArray private_key;
};

#endif // RSAKEYPAIRGENERATOR_H
