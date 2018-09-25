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
#include <sys/socket.h>
#include <netinet/in.h>
#define WEBRTC_MAC 1
#define WEBRTC_POSIX 1
#endif //Q_OS_MAC

#include "portableendian.h"

#include <pc/peerconnection.h>
#include <api/datachannelinterface.h>
#include <api/jsep.h>
#include <rtc_base/refcount.h>
#include <rtc_base/openssladapter.h>
#include <api/audio_codecs/builtin_audio_decoder_factory.h>
#include <api/audio_codecs/builtin_audio_encoder_factory.h>
#include <media/engine/internaldecoderfactory.h>
#include <media/engine/internalencoderfactory.h>
#include <media/engine/webrtcmediaengine.h>
#include "modules/audio_processing/include/audio_processing.h"

class PeerConnectionHandler : public QObject,
    public webrtc::DataChannelObserver,
    public webrtc::CreateSessionDescriptionObserver,
    public webrtc::SetSessionDescriptionObserver,
    public webrtc::PeerConnectionObserver
{
    Q_OBJECT

public:
    PeerConnectionHandler();
    ~PeerConnectionHandler();

    static void Initialize();

    void OnSignalingChange(webrtc::PeerConnectionInterface::SignalingState new_state);
    void OnAddStream(rtc::scoped_refptr<webrtc::MediaStreamInterface> stream);
    void OnRemoveStream(rtc::scoped_refptr<webrtc::MediaStreamInterface> stream);
    void OnDataChannel(rtc::scoped_refptr<webrtc::DataChannelInterface> data_channel);
    void OnRenegotiationNeeded();
    void OnIceConnectionChange(webrtc::PeerConnectionInterface::IceConnectionState new_state);
    void OnIceGatheringChange(webrtc::PeerConnectionInterface::IceGatheringState new_state);
    void OnIceCandidate(const webrtc::IceCandidateInterface* candidate);
    void OnIceCandidatesRemoved(const std::vector<cricket::Candidate>& candidates);
    void OnIceConnectionReceivingChange(bool receiving);
    void OnAddTrack(rtc::scoped_refptr<webrtc::RtpReceiverInterface> receiver, const std::vector<rtc::scoped_refptr<webrtc::MediaStreamInterface>>& streams);
    void OnTrack(rtc::scoped_refptr<webrtc::RtpTransceiverInterface> transceiver);
    void OnRemoveTrack(rtc::scoped_refptr<webrtc::RtpReceiverInterface> receiver);
    void OnInterestingUsage(int usage_pattern);

    void OnSuccess();

    void OnSuccess(webrtc::SessionDescriptionInterface* desc);
    void OnFailure(webrtc::RTCError error);

    void OnFailure(const std::string& error);

    void AddRef() const;
    rtc::RefCountReleaseStatus Release() const;

    void OnStateChange();
    void OnMessage(const webrtc::DataBuffer& buffer);
    void OnBufferedAmountChange(uint64_t previous_amount);

public Q_SLOTS:
    void Connect();
    void Disconnect();
    void ServerConnected();
    void ServerDisconnected();
    void ClientMessageReceived(const QString &message);
    void ClientBinaryMessageReceived(const QByteArray &message);
    void ClientDisconnected();
    void MessageReceived(const QString &message);
    void BinaryMessageReceived(const QByteArray &message);

private:
    rtc::scoped_refptr<webrtc::PeerConnectionInterface> remote_peer_connection;

    static webrtc::DataChannelInit * data_channel_init;
    static rtc::scoped_refptr<webrtc::PeerConnectionFactoryInterface> peer_connection_factory;

    QWebSocketServer * signaling_server;
    QWebSocket * signaling_socket;
    QWebSocket * server_side_signaling_socket;

    QList<QWebSocket *> client_sockets;

    static rtc::Thread * networking_thread;
    static rtc::Thread * worker_thread;
    static rtc::Thread * signaling_thread;

    static std::unique_ptr<rtc::RTCCertificateGeneratorInterface> certificate_generator;
};

#endif // PEERCONNECTIONHANDLER_H
