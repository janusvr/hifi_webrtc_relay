#include "peerconnectionhandler.h"

//TODO: handle multiple clients

PeerConnectionHandler::PeerConnectionHandler()
{
    signaling_server = new QWebSocketServer(QStringLiteral("Signaling Server"), QWebSocketServer::NonSecureMode, this);

    if (signaling_server->listen(QHostAddress::LocalHost, 8142)) {
        connect(signaling_server, &QWebSocketServer::newConnection, this, &PeerConnectionHandler::Connect);
        connect(signaling_server, &QWebSocketServer::closed, this, &PeerConnectionHandler::Disconnect);
    }
}

PeerConnectionHandler::~PeerConnectionHandler()
{
    for (int i = 0; i < client_sockets.size(); i++)
    {
        client_sockets[i]->close();
    }
    signaling_server->close();
}

void PeerConnectionHandler::Connect()
{
    QWebSocket *s = signaling_server->nextPendingConnection();

    //Loop through client sockets, if different peerAddress and peerPort then add the new socket
    bool new_socket = true;
    for (int i = 0; i < client_sockets.size(); i++)
    {
        if (client_sockets[i]->peerAddress() == s->peerAddress() && client_sockets[i]->peerPort() == s->peerPort()) {
            new_socket = false;
            break;
        }
    }

    qDebug() << "connect" << s << s->peerAddress() << s->peerPort();
    if (new_socket)
    {
        qDebug() << "new client";
        connect(s, &QWebSocket::textMessageReceived, this, &PeerConnectionHandler::ClientMessageReceived);
        connect(s, &QWebSocket::disconnected, this, &PeerConnectionHandler::ClientDisconnected);

        client_sockets.push_back(s);

        s->sendTextMessage("connected");
    }
}

void PeerConnectionHandler::Disconnect()
{

}

void PeerConnectionHandler::ServerConnected()
{
    //qDebug() << "PeerConnectionHandler::ServerConnected()";
}

void PeerConnectionHandler::ServerDisconnected()
{
    //qDebug() << "PeerConnectionHandler::ServerDisconnected()";
}

void PeerConnectionHandler::ClientMessageReceived(const QString &message)
{
    qDebug() << "PeerConnectionHandler::ClientMessageReceived() - " << message;
    QWebSocket *client = qobject_cast<QWebSocket *>(sender());

    QJsonDocument doc;
    doc = QJsonDocument::fromJson(message.toLatin1());
    QJsonObject obj = doc.object();
    QString type = obj["type"].toString();
    if (type == "offer")
    {
        rtcdcpp::RTCConfiguration config;
        config.ice_servers.emplace_back(rtcdcpp::RTCIceServer{"stun3.l.google.com", 19302});

        std::function<void(rtcdcpp::PeerConnection::IceCandidate)> onLocalIceCandidate = [this,client](rtcdcpp::PeerConnection::IceCandidate candidate) {
            QJsonObject candidateObject;
            candidateObject.insert("type", QJsonValue::fromVariant("candidate"));
            QJsonObject candidateObject2;
            candidateObject2.insert("candidate", QJsonValue::fromVariant(QString::fromStdString(candidate.candidate)));
            candidateObject2.insert("sdpMid", QJsonValue::fromVariant(QString::fromStdString(candidate.sdpMid)));
            candidateObject2.insert("sdpMLineIndex", QJsonValue::fromVariant(candidate.sdpMLineIndex));
            candidateObject.insert("candidate", candidateObject2);
            QJsonDocument candidateDoc(candidateObject);

            qDebug() << "candidate: " << candidateDoc.toJson();
            client->sendTextMessage(QString::fromStdString(candidateDoc.toJson().toStdString()));
        };

        std::function<void(std::shared_ptr<rtcdcpp::DataChannel> channel)> onDataChannel = [this](std::shared_ptr<rtcdcpp::DataChannel> channel) {
            qDebug() << "datachannel" << QString::fromStdString(channel->GetLabel());
            QString label = QString::fromStdString(channel->GetLabel());
            if (label == "domain_server_dc") {
                std::function<void(std::string)> onStringMessageCallback = [this](std::string message) {
                    qDebug() << "domainserverdcmessage" << QString::fromStdString(message);
                };
                channel->SetOnStringMsgCallback(onStringMessageCallback);

                std::function<void(rtcdcpp::ChunkPtr)> onBinaryMessageCallback = [this](rtcdcpp::ChunkPtr message) {
                    QByteArray m = QByteArray((char *) message->Data(), message->Length());
                    qDebug() << "domainserverdcbinarymessage" << m;
                };
                channel->SetOnBinaryMsgCallback(onBinaryMessageCallback);

                std::function<void()> onClosed = [this]() {
                    qDebug() << "domainserverdcclosed";
                    this->SetDomainServerDC(nullptr);
                };
                channel->SetOnClosedCallback(onClosed);

                qDebug() << "PeerConnectionHandler::onDataChannel() - Registering domain server data channel";
                this->SetDomainServerDC(channel);
                this->SendDomainServerMessage(QString("message"));
            }
            else if (label == "audio_mixer_dc") {
                std::function<void(std::string)> onStringMessageCallback = [this](std::string message) {
                    qDebug() << "audiomixerdcmessage" << QString::fromStdString(message);
                };
                channel->SetOnStringMsgCallback(onStringMessageCallback);

                std::function<void(rtcdcpp::ChunkPtr)> onBinaryMessageCallback = [this](rtcdcpp::ChunkPtr message) {
                    QByteArray m = QByteArray((char *) message->Data(), message->Length());
                    qDebug() << "audiomixerdcbinarymessage" << m;
                };
                channel->SetOnBinaryMsgCallback(onBinaryMessageCallback);

                std::function<void()> onClosed = [this]() {
                    qDebug() << "audiomixerdcclosed";
                    this->SetAudioMixerDC(nullptr);
                };
                channel->SetOnClosedCallback(onClosed);

                qDebug() << "PeerConnectionHandler::onDataChannel() - Registering audio mixer data channel";
                this->SetAudioMixerDC(channel);
                this->SendAudioMixerMessage(QString("message"));
            }
            else if (label == "avatar_mixer_dc") {
                std::function<void(std::string)> onStringMessageCallback = [this](std::string message) {
                    qDebug() << "avatarmixerdcmessage" << QString::fromStdString(message);
                };
                channel->SetOnStringMsgCallback(onStringMessageCallback);

                std::function<void(rtcdcpp::ChunkPtr)> onBinaryMessageCallback = [this](rtcdcpp::ChunkPtr message) {
                    QByteArray m = QByteArray((char *) message->Data(), message->Length());
                    qDebug() << "avatarmixerdcbinarymessage" << m;
                };
                channel->SetOnBinaryMsgCallback(onBinaryMessageCallback);

                std::function<void()> onClosed = [this]() {
                    qDebug() << "avatarmixerdcclosed";
                    this->SetAvatarMixerDC(nullptr);
                };
                channel->SetOnClosedCallback(onClosed);

                qDebug() << "PeerConnectionHandler::onDataChannel() - Registering avatar mixer data channel";
                this->SetAvatarMixerDC(channel);
                this->SendAvatarMixerMessage(QString("message"));
            }
            else if (label == "entity_server_dc") {
                std::function<void(std::string)> onStringMessageCallback = [this](std::string message) {
                    qDebug() << "entityserverdcmessage" << QString::fromStdString(message);
                };
                channel->SetOnStringMsgCallback(onStringMessageCallback);

                std::function<void(rtcdcpp::ChunkPtr)> onBinaryMessageCallback = [this](rtcdcpp::ChunkPtr message) {
                    QByteArray m = QByteArray((char *) message->Data(), message->Length());
                    qDebug() << "entityserverdcbinarymessage" << m;
                };
                channel->SetOnBinaryMsgCallback(onBinaryMessageCallback);

                std::function<void()> onClosed = [this]() {
                    qDebug() << "entityserverdcclosed";
                    this->SetEntityServerDC(nullptr);
                };
                channel->SetOnClosedCallback(onClosed);

                qDebug() << "PeerConnectionHandler::onDataChannel() - Registering entity server data channel";
                this->SetEntityServerDC(channel);
                this->SendEntityServerMessage(QString("message"));
            }
            else if (label == "entity_script_server_dc") {
                std::function<void(std::string)> onStringMessageCallback = [this](std::string message) {
                    qDebug() << "entityscriptserverdcmessage" << QString::fromStdString(message);
                };
                channel->SetOnStringMsgCallback(onStringMessageCallback);

                std::function<void(rtcdcpp::ChunkPtr)> onBinaryMessageCallback = [this](rtcdcpp::ChunkPtr message) {
                    QByteArray m = QByteArray((char *) message->Data(), message->Length());
                    qDebug() << "entityscriptserverdcbinarymessage" << m;
                };
                channel->SetOnBinaryMsgCallback(onBinaryMessageCallback);

                std::function<void()> onClosed = [this]() {
                    qDebug() << "entityscriptserverdcclosed";
                    this->SetEntityScriptServerDC(nullptr);
                };
                channel->SetOnClosedCallback(onClosed);

                qDebug() << "PeerConnectionHandler::onDataChannel() - Registering entity script server data channel";
                this->SetEntityScriptServerDC(channel);
                this->SendEntityScriptServerMessage(QString("message"));
            }
            else if (label == "messages_mixer_dc") {
                std::function<void(std::string)> onStringMessageCallback = [this](std::string message) {
                    qDebug() << "messagesmixerdcmessage" << QString::fromStdString(message);
                };
                channel->SetOnStringMsgCallback(onStringMessageCallback);

                std::function<void(rtcdcpp::ChunkPtr)> onBinaryMessageCallback = [this](rtcdcpp::ChunkPtr message) {
                    QByteArray m = QByteArray((char *) message->Data(), message->Length());
                    qDebug() << "messagesmixerdcbinarymessage" << m;
                };
                channel->SetOnBinaryMsgCallback(onBinaryMessageCallback);

                std::function<void()> onClosed = [this]() {
                    qDebug() << "messagesmixerdcclosed";
                    this->SetMessagesMixerDC(nullptr);
                };
                channel->SetOnClosedCallback(onClosed);

                qDebug() << "PeerConnectionHandler::onDataChannel() - Registering messages mixer data channel";
                this->SetMessagesMixerDC(channel);
                this->SendMessagesMixerMessage(QString("message"));
            }
            else if (label == "asset_server_dc") {
                std::function<void(std::string)> onStringMessageCallback = [this](std::string message) {
                    qDebug() << "assetserverdcmessage" << QString::fromStdString(message);
                };
                channel->SetOnStringMsgCallback(onStringMessageCallback);

                std::function<void(rtcdcpp::ChunkPtr)> onBinaryMessageCallback = [this](rtcdcpp::ChunkPtr message) {
                    QByteArray m = QByteArray((char *) message->Data(), message->Length());
                    qDebug() << "assetserverdcbinarymessage" << m;
                };
                channel->SetOnBinaryMsgCallback(onBinaryMessageCallback);

                std::function<void()> onClosed = [this]() {
                    qDebug() << "assetserverdcclosed";
                    this->SetAssetServerDC(nullptr);
                };
                channel->SetOnClosedCallback(onClosed);

                qDebug() << "PeerConnectionHandler::onDataChannel() - Registering asset server data channel";
                this->SetAssetServerDC(channel);
                this->SendAssetServerMessage(QString("message"));
            }
        };

        remote_peer_connection = std::make_shared<rtcdcpp::PeerConnection>(config, onLocalIceCandidate, onDataChannel);

        remote_peer_connection->ParseOffer(obj["sdp"].toString().toStdString());
        QJsonObject answerObject;
        answerObject.insert("type", QJsonValue::fromVariant("answer"));
        answerObject.insert("sdp", QJsonValue::fromVariant(QString::fromStdString(remote_peer_connection->GenerateAnswer())));
        QJsonDocument answerDoc(answerObject);

        qDebug() << "Sending Answer: " << answerDoc.toJson();
        client->sendTextMessage(QString::fromStdString(answerDoc.toJson().toStdString()));
    }
    else if (type == "candidate")
    {
        qDebug() << "remote candidate";
        QJsonObject c = obj["candidate"].toObject();
        remote_peer_connection->SetRemoteIceCandidate("a=" + c["candidate"].toString().toStdString());
    }
}

void PeerConnectionHandler::ClientDisconnected()
{
    QWebSocket *s = qobject_cast<QWebSocket *>(sender());
    if (s) {
        client_sockets.removeAll(s);
        s->deleteLater();
    }
}
