#ifndef PEERCONNECTIONHANDLER_H
#define PEERCONNECTIONHANDLER_H

#include <QObject>
#include <QDebug>
#include <QtWebSockets/QtWebSockets>

#ifdef Q_OS_WIN
#include <winsock2.h>
#include <WS2tcpip.h>
#endif //Q_OS_WIN

#ifdef Q_OS_MAC
#define SPDLOG_DISABLED
#include <sys/socket.h>
#include <netinet/in.h>
#endif //Q_OS_MAC

#include "portableendian.h"

#include <rtcdcpp/PeerConnection.hpp>

class PeerConnectionHandler : public QObject
{
    Q_OBJECT

public:
    PeerConnectionHandler();
    ~PeerConnectionHandler();

    void SetDomainServerDC(std::shared_ptr<rtcdcpp::DataChannel> d) {domain_server_dc = d;}
    void SetAudioMixerDC(std::shared_ptr<rtcdcpp::DataChannel> d) {audio_mixer_dc = d;}
    void SetAvatarMixerDC(std::shared_ptr<rtcdcpp::DataChannel> d) {avatar_mixer_dc = d;}
    void SetMessagesMixerDC(std::shared_ptr<rtcdcpp::DataChannel> d) {messages_mixer_dc = d;}
    void SetAssetServerDC(std::shared_ptr<rtcdcpp::DataChannel> d) {asset_server_dc = d;}
    void SetEntityServerDC(std::shared_ptr<rtcdcpp::DataChannel> d) {entity_server_dc = d;}
    void SetEntityScriptServerDC(std::shared_ptr<rtcdcpp::DataChannel> d) {entity_script_server_dc = d;}

    void SendDomainServerMessage(QString message) {domain_server_dc->SendString(message.toStdString());}
    void SendAudioMixerMessage(QString message) {audio_mixer_dc->SendString(message.toStdString());}
    void SendAvatarMixerMessage(QString message) {avatar_mixer_dc->SendString(message.toStdString());}
    void SendMessagesMixerMessage(QString message) {messages_mixer_dc->SendString(message.toStdString());}
    void SendAssetServerMessage(QString message) {asset_server_dc->SendString(message.toStdString());}
    void SendEntityServerMessage(QString message) {entity_server_dc->SendString(message.toStdString());}
    void SendEntityScriptServerMessage(QString message) {entity_script_server_dc->SendString(message.toStdString());}

    void SendDomainServerMessage(QByteArray message) {domain_server_dc->SendBinary((const uint8_t *) message.data(), message.size());}
    void SendAudioMixerMessage(QByteArray message) {audio_mixer_dc->SendBinary((const uint8_t *) message.data(), message.size());}
    void SendAvatarMixerMessage(QByteArray message) {avatar_mixer_dc->SendBinary((const uint8_t *) message.data(), message.size());}
    void SendMessagesMixerMessage(QByteArray message) {messages_mixer_dc->SendBinary((const uint8_t *) message.data(), message.size());}
    void SendAssetServerMessage(QByteArray message) {asset_server_dc->SendBinary((const uint8_t *) message.data(), message.size());}
    void SendEntityServerMessage(QByteArray message) {entity_server_dc->SendBinary((const uint8_t *) message.data(), message.size());}
    void SendEntityScriptServerMessage(QByteArray message) {entity_script_server_dc->SendBinary((const uint8_t *) message.data(), message.size());}

    QList<QWebSocket *> GetClientSockets() {return client_sockets;}

public Q_SLOTS:
    void Connect();
    void Disconnect();
    void ServerConnected();
    void ServerDisconnected();
    void ClientMessageReceived(const QString &message);
    void ClientDisconnected();

private:
    std::shared_ptr<rtcdcpp::PeerConnection> remote_peer_connection;

    QWebSocketServer * signaling_server;

    std::shared_ptr<rtcdcpp::DataChannel> domain_server_dc;
    std::shared_ptr<rtcdcpp::DataChannel> audio_mixer_dc;
    std::shared_ptr<rtcdcpp::DataChannel> avatar_mixer_dc;
    std::shared_ptr<rtcdcpp::DataChannel> messages_mixer_dc;
    std::shared_ptr<rtcdcpp::DataChannel> entity_server_dc;
    std::shared_ptr<rtcdcpp::DataChannel> entity_script_server_dc;
    std::shared_ptr<rtcdcpp::DataChannel> asset_server_dc;

    QList<QWebSocket *> client_sockets;

};

#endif // PEERCONNECTIONHANDLER_H
