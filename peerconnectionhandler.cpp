#include "peerconnectionhandler.h"

webrtc::DataChannelInit * PeerConnectionHandler::data_channel_init = nullptr;
rtc::scoped_refptr<webrtc::PeerConnectionFactoryInterface> PeerConnectionHandler::peer_connection_factory = nullptr;

PeerConnectionHandler::PeerConnectionHandler()
{
    // 2. Create a new PeerConnection.
    webrtc::PeerConnectionInterface::RTCConfiguration config;
    config.enable_rtp_data_channel = true;
    config.enable_dtls_srtp = false;

    local_peer_connection = peer_connection_factory->CreatePeerConnection(config, nullptr, nullptr, this);
    remote_peer_connection = peer_connection_factory->CreatePeerConnection(config, nullptr, nullptr, this);

    rtc::scoped_refptr<webrtc::DataChannelInterface> domain_data_channel = local_peer_connection->CreateDataChannel("domain_data_channel", data_channel_init);
    rtc::scoped_refptr<webrtc::DataChannelInterface> audio_mixer_data_channel = local_peer_connection->CreateDataChannel("audio_mixer_data_channel", data_channel_init);
    rtc::scoped_refptr<webrtc::DataChannelInterface> asset_server_data_channel = local_peer_connection->CreateDataChannel("asset_server_data_channel", data_channel_init);
    rtc::scoped_refptr<webrtc::DataChannelInterface> avatar_mixer_data_channel = local_peer_connection->CreateDataChannel("avatar_mixer_data_channel", data_channel_init);
    rtc::scoped_refptr<webrtc::DataChannelInterface> messages_mixer_data_channel = local_peer_connection->CreateDataChannel("messages_mixer_data_channel", data_channel_init);
    rtc::scoped_refptr<webrtc::DataChannelInterface> entity_server_data_channel = local_peer_connection->CreateDataChannel("entity_server_data_channel", data_channel_init);
    rtc::scoped_refptr<webrtc::DataChannelInterface> entity_script_server_data_channel = local_peer_connection->CreateDataChannel("entity_script_server_data_channel", data_channel_init);

    domain_data_channel->RegisterObserver(this);
    audio_mixer_data_channel->RegisterObserver(this);
    asset_server_data_channel->RegisterObserver(this);
    avatar_mixer_data_channel->RegisterObserver(this);
    messages_mixer_data_channel->RegisterObserver(this);
    entity_server_data_channel->RegisterObserver(this);
    entity_script_server_data_channel->RegisterObserver(this);

    local_peer_connection->CreateOffer(this, webrtc::PeerConnectionInterface::RTCOfferAnswerOptions());
}

PeerConnectionHandler::~PeerConnectionHandler()
{

}

void PeerConnectionHandler::Initialize()
{
    // 1. Create PeerConnectionFactoryInterface if it doesn't exist.
    rtc::Thread * networking_thread = new rtc::Thread();
    networking_thread->Start();
    rtc::Thread * worker_thread = new rtc::Thread();
    worker_thread->Start();
    rtc::Thread * signaling_thread = new rtc::Thread();
    signaling_thread->Start();

    peer_connection_factory = webrtc::CreateModularPeerConnectionFactory(networking_thread,
                                                                         worker_thread,
                                                                         signaling_thread,
                                                                         nullptr,
                                                                         webrtc::CreateCallFactory(),
                                                                         webrtc::CreateRtcEventLogFactory());

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
    //data_channel->RegisterObserver(this);
}

void PeerConnectionHandler::OnRenegotiationNeeded()
{

}

void PeerConnectionHandler::OnIceConnectionChange(webrtc::PeerConnectionInterface::IceConnectionState new_state)
{

}

void PeerConnectionHandler::OnIceGatheringChange(webrtc::PeerConnectionInterface::IceGatheringState new_state)
{
    qDebug() << "gatherstate" << new_state;
    if (new_state == webrtc::PeerConnectionInterface::kIceGatheringComplete)
    {
        // 4. Generate an answer to the remote offer by calling CreateAnswer and send it
        // back to the remote peer.
        remote_peer_connection->CreateAnswer(this, webrtc::PeerConnectionInterface::RTCOfferAnswerOptions());
    }
}

void PeerConnectionHandler::OnIceCandidate(const webrtc::IceCandidateInterface* candidate)
{
    std::string l;
    candidate->ToString(&l);
    qDebug() << "PeerConnectionHandler::OnIceCandidate()" << QString::fromStdString(l);

    // 6. Provide the remote ICE candidates by calling AddIceCandidate.
    // 7. Once a candidate has been gathered, the PeerConnection will call the
    // observer function OnIceCandidate. Send these candidates to the remote peer.
    remote_peer_connection->AddIceCandidate(candidate);

    // 6. Provide the remote ICE candidates by calling AddIceCandidate.
    // 7. Once a candidate has been gathered, the PeerConnection will call the
    // observer function OnIceCandidate. Send these candidates to the remote peer.
    local_peer_connection->AddIceCandidate(candidate);
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
    if (QString::fromStdString(desc->type()) == "offer"){
        // 3. Provide the remote offer to the new PeerConnection object by calling
        // SetRemoteDescription.
        local_peer_connection->SetLocalDescription(this,desc);
        remote_peer_connection->SetRemoteDescription(this,desc);
    }
    else if (QString::fromStdString(desc->type()) == "answer"){
        // 5. Provide the local answer to the new PeerConnection by calling
        // SetLocalDescription with the answer.
        local_peer_connection->SetRemoteDescription(this, desc);
        remote_peer_connection->SetLocalDescription(this, desc);
    }
}

void PeerConnectionHandler::OnSuccess()
{
    //qDebug() << "PeerConnectionHandler::OnSuccess() - Set Session Description WebRTC";
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
