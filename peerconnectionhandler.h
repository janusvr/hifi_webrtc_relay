#ifndef PEERCONNECTIONHANDLER_H
#define PEERCONNECTIONHANDLER_H

#include <QObject>

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

class PeerConnectionHandler : public webrtc::PeerConnectionObserver //,
        //public webrtc::CreateSessionDescriptionObserver,
        //public webrtc::DataChannelObserver
{
public:
    PeerConnectionHandler();
    ~PeerConnectionHandler();

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
};

#endif // PEERCONNECTIONHANDLER_H
