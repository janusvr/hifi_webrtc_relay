#include "peerconnectionhandler.h"

PeerConnectionHandler::PeerConnectionHandler()
{

}

PeerConnectionHandler::~PeerConnectionHandler()
{

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
