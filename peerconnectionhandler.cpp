#include "peerconnectionhandler.h"

webrtc::DataChannelInit * PeerConnectionHandler::data_channel_init = nullptr;
rtc::scoped_refptr<webrtc::PeerConnectionFactoryInterface> PeerConnectionHandler::peer_connection_factory = nullptr;
rtc::Thread * PeerConnectionHandler::networking_thread = nullptr;
rtc::Thread * PeerConnectionHandler::worker_thread = nullptr;
rtc::Thread * PeerConnectionHandler::signaling_thread = nullptr;
std::unique_ptr<rtc::RTCCertificateGeneratorInterface> PeerConnectionHandler::certificate_generator = nullptr;

PeerConnectionHandler::PeerConnectionHandler()
{
    // 2. Create a new PeerConnection.
    webrtc::PeerConnectionInterface::RTCConfiguration config(webrtc::PeerConnectionInterface::RTCConfigurationType::kSafe);
    config.certificates.push_back(
                rtc::RTCCertificateGenerator::GenerateCertificate(rtc::KeyParams(),
                                                                           absl::nullopt));

    remote_peer_connection = peer_connection_factory->CreatePeerConnection(config, nullptr, std::move(certificate_generator), this);

    signaling_server = new QWebSocketServer(QStringLiteral("Signaling Server"), QWebSocketServer::NonSecureMode, this);

    if (signaling_server->listen(QHostAddress::LocalHost, 8108)) {
        connect(signaling_server, &QWebSocketServer::newConnection,
                this, &PeerConnectionHandler::Connect);
        connect(signaling_server, &QWebSocketServer::closed, this, &PeerConnectionHandler::Disconnect);
    }

    signaling_socket = new QWebSocket();
    connect(signaling_socket, &QWebSocket::connected, this, &PeerConnectionHandler::ServerConnected);
    connect(signaling_socket, &QWebSocket::disconnected, this, &PeerConnectionHandler::ServerDisconnected);
    connect(signaling_socket, &QWebSocket::textMessageReceived, this, &PeerConnectionHandler::MessageReceived);
    connect(signaling_socket, &QWebSocket::binaryMessageReceived, this, &PeerConnectionHandler::BinaryMessageReceived);

    signaling_socket->open(QUrl("ws://localhost:8108"));
}

PeerConnectionHandler::~PeerConnectionHandler()
{
    signaling_socket->close();
    signaling_server->close();
}

void PeerConnectionHandler::Connect()
{
    QWebSocket *s = signaling_server->nextPendingConnection();

    qDebug() << "connect" << signaling_socket->localAddress() << signaling_socket->localPort() << s << s->peerAddress() << s->peerPort();
    if (!client_sockets.contains(s) && !(s->peerAddress() == signaling_socket->localAddress() && s->peerPort() == signaling_socket->localPort()))
    {
        qDebug() << "new client";
        connect(s, &QWebSocket::textMessageReceived, this, &PeerConnectionHandler::ClientMessageReceived);
        connect(s, &QWebSocket::binaryMessageReceived, this, &PeerConnectionHandler::ClientBinaryMessageReceived);
        connect(s, &QWebSocket::disconnected, this, &PeerConnectionHandler::ClientDisconnected);

        client_sockets.push_back(s);

        s->sendTextMessage("connected");
    }
    else if (s->peerAddress() == signaling_socket->localAddress() && s->peerPort() == signaling_socket->localPort())
    {
        server_side_signaling_socket = s;
    }
}

void PeerConnectionHandler::Disconnect()
{

}

void PeerConnectionHandler::ServerConnected()
{
    qDebug() << "connected";
}

void PeerConnectionHandler::ServerDisconnected()
{
    qDebug() << "disconnected";
}

void PeerConnectionHandler::ClientBinaryMessageReceived(const QByteArray &message)
{
    qDebug() << "clientmessage" << message;
    server_side_signaling_socket->sendBinaryMessage(message);
}

void PeerConnectionHandler::ClientMessageReceived(const QString &message)
{
    qDebug() << "clientmessage" << message;
    server_side_signaling_socket->sendTextMessage(message);
}

void PeerConnectionHandler::ClientDisconnected()
{
    QWebSocket *s = qobject_cast<QWebSocket *>(sender());
    if (s) {
        client_sockets.removeAll(s);
        s->deleteLater();
    }
}

void PeerConnectionHandler::BinaryMessageReceived(const QByteArray &message)
{
    qDebug() << "message" << message;

    QJsonDocument doc;
    doc = QJsonDocument::fromJson(message);
    QJsonObject obj = doc.object();
    QString type = obj["type"].toString();
    if (type == "offer")
    {
        QString sdp = obj["sdp"].toString();
        std::unique_ptr<webrtc::SessionDescriptionInterface> desc = webrtc::CreateSessionDescription(webrtc::SdpType::kOffer, sdp.toStdString());
        qDebug() << "message" << type << sdp;
        remote_peer_connection->SetRemoteDescription(this,desc.get());
    }
    else if (type == "ice")
    {
        QString sdp = obj["sdp"].toString();
        //std::unique_ptr<SessionDescriptionInterface> desc = CreateSessionDescription(webrtc::SdpType::kAnswer, sdp.toStdString());
        qDebug() << "message" << type << sdp;
    }
}

void PeerConnectionHandler::MessageReceived(const QString &message)
{
    //qDebug() << "message" << message;
    QJsonDocument doc;
    doc = QJsonDocument::fromJson(message.toLatin1());
    QJsonObject obj = doc.object();
    QString type = obj["type"].toString();
    if (type == "offer")
    {
        QString sdp = obj["sdp"].toString();
        std::unique_ptr<webrtc::SessionDescriptionInterface> desc = webrtc::CreateSessionDescription(webrtc::SdpType::kOffer, sdp.toStdString());
        qDebug() << "message" << type << sdp;
        remote_peer_connection->SetRemoteDescription(this,desc.get());
    }
    else if (type == "ice")
    {
        QString sdp = obj["sdp"].toString();
        //std::unique_ptr<SessionDescriptionInterface> desc = CreateSessionDescription(webrtc::SdpType::kAnswer, sdp.toStdString());
        qDebug() << "message" << type << sdp;
    }
}

void PeerConnectionHandler::Initialize()
{
    // 1. Create PeerConnectionFactoryInterface if it doesn't exist.
    rtc::InitializeSSL();
    rtc::InitRandom(rtc::Time());
    rtc::ThreadManager::Instance()->WrapCurrentThread();

    networking_thread = new rtc::Thread();
    networking_thread->Start();
    worker_thread = new rtc::Thread();
    worker_thread->Start();
    signaling_thread = new rtc::Thread();
    signaling_thread->Start();

    std::unique_ptr<cricket::MediaEngineInterface> media_engine =
        cricket::WebRtcMediaEngineFactory::Create(
            nullptr /* adm */, webrtc::CreateBuiltinAudioEncoderFactory(),
            webrtc::CreateBuiltinAudioDecoderFactory(),
            absl::make_unique<webrtc::InternalEncoderFactory>(),
            absl::make_unique<webrtc::InternalDecoderFactory>(),
            nullptr /* audio_mixer */, webrtc::AudioProcessingBuilder().Create());

    peer_connection_factory = webrtc::CreateModularPeerConnectionFactory(networking_thread,
                                                                         worker_thread,
                                                                         signaling_thread,
                                                                         std::move(media_engine),
                                                                         webrtc::CreateCallFactory(),
                                                                         webrtc::CreateRtcEventLogFactory());

    certificate_generator.reset(new rtc::RTCCertificateGenerator(signaling_thread, worker_thread));
    data_channel_init = new webrtc::DataChannelInit();
}

void PeerConnectionHandler::OnSignalingChange(webrtc::PeerConnectionInterface::SignalingState new_state)
{

}

void PeerConnectionHandler::OnAddStream(rtc::scoped_refptr<webrtc::MediaStreamInterface> stream)
{

}

void PeerConnectionHandler::OnRemoveStream(rtc::scoped_refptr<webrtc::MediaStreamInterface> stream)
{

}

void PeerConnectionHandler::OnDataChannel(rtc::scoped_refptr<webrtc::DataChannelInterface> data_channel)
{
    qDebug() << "PeerConnectionHandler::OnDataChannel() - " << QString::fromStdString(data_channel->label());
    data_channel->RegisterObserver(this);
}

void PeerConnectionHandler::OnRenegotiationNeeded()
{

}

void PeerConnectionHandler::OnIceConnectionChange(webrtc::PeerConnectionInterface::IceConnectionState new_state)
{

}

void PeerConnectionHandler::OnIceGatheringChange(webrtc::PeerConnectionInterface::IceGatheringState new_state)
{

}

void PeerConnectionHandler::OnIceCandidate(const webrtc::IceCandidateInterface* candidate)
{
    std::string l;
    candidate->ToString(&l);
    qDebug() << "PeerConnectionHandler::OnIceCandidate()" << QString::fromStdString(l);
}

void PeerConnectionHandler::OnIceCandidatesRemoved(const std::vector<cricket::Candidate>& candidates)
{

}

void PeerConnectionHandler::OnIceConnectionReceivingChange(bool receiving)
{

}

void PeerConnectionHandler::OnAddTrack(rtc::scoped_refptr<webrtc::RtpReceiverInterface> receiver, const std::vector<rtc::scoped_refptr<webrtc::MediaStreamInterface>>& streams)
{

}

void PeerConnectionHandler::OnTrack(rtc::scoped_refptr<webrtc::RtpTransceiverInterface> transceiver)
{

}

void PeerConnectionHandler::OnRemoveTrack(rtc::scoped_refptr<webrtc::RtpReceiverInterface> receiver)
{

}

void PeerConnectionHandler::OnInterestingUsage(int usage_pattern)
{

}

void PeerConnectionHandler::OnSuccess(webrtc::SessionDescriptionInterface* desc)
{
    qDebug() << "PeerConnectionHandler::OnSuccess() - Create Session Description WebRTC: " << QString::fromStdString(desc->type());
    if (QString::fromStdString(desc->type()) == "answer"){
        // 5. Provide the local answer to the new PeerConnection by calling
        // SetLocalDescription with the answer.
        remote_peer_connection->SetLocalDescription(this, desc);
        std::string out;
        desc->ToString(&out);
        client_sockets.last()->sendTextMessage(QString::fromStdString(out));
    }
}

void PeerConnectionHandler::OnSuccess()
{
    //qDebug() << "PeerConnectionHandler::OnSuccess() - Set Session Description WebRTC";
    remote_peer_connection->CreateAnswer(this, webrtc::PeerConnectionInterface::RTCOfferAnswerOptions());
}

void PeerConnectionHandler::OnFailure(webrtc::RTCError error)
{
    qDebug() << "PeerConnectionHandler::OnFailure() - Session Description WebRTC Error: " << error.message();
}

void PeerConnectionHandler::OnFailure(const std::string& error)
{
    qDebug() << "PeerConnectionHandler::OnFailure() - Session Description WebRTC Error: " << QString::fromStdString(error);
}

void PeerConnectionHandler::AddRef() const
{

}

rtc::RefCountReleaseStatus PeerConnectionHandler::Release() const
{

}

void PeerConnectionHandler::OnStateChange()
{
    qDebug() << "STATE CHANGE";
}

void PeerConnectionHandler::OnMessage(const webrtc::DataBuffer& buffer)
{
    qDebug() << "RECEIVED MESSAGE";
}

void PeerConnectionHandler::OnBufferedAmountChange(uint64_t previous_amount)
{

}
