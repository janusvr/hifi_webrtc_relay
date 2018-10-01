var signalServer = new WebSocket('ws://localhost:8118');
var domain_sendChannel;
var audio_sendChannel;
var avatar_sendChannel;
var entity_sendChannel;
var entityscript_sendChannel;
var messages_sendChannel;
var asset_sendChannel;
var remoteCandidates = [];
var have_answer = false;

signalServer.onopen = function (event) {

};

function gotDescription(desc) {
    localConnection.setLocalDescription(desc);
    var msg ={
        type: 'offer',
        sdp: desc.sdp
    };
    console.log('Offer from localConnection \n' + msg.sdp);

    signalServer.send(JSON.stringify(msg));
}

function iceCallback(event) {
    console.log('local ice callback');
    if (event.candidate) {
        var msg ={
            type: 'candidate',
            candidate: event.candidate
        };
        console.log('Local ICE candidate: \n' + event.candidate.candidate + '\n' + event.candidate.sdpMid + '\n' + event.candidate.sdpMLineIndex);
        signalServer.send(JSON.stringify(msg));
    }
}

function domainMessage(event) {
    console.log('domain_server message ' + event.data);
    //domain_sendChannel.send('domain_message');
}

function audioMixerMessage(event) {
    console.log('audio message ' + event.data);
    //audio_sendChannel.send('audio_message');
}

function avatarMixerMessage(event) {
    console.log('avatar message ' + event.data);
    //avatar_sendChannel.send('avatar_message');
}

function entityServerMessage(event) {
    console.log('entity message ' + event.data);
    //entity_sendChannel.send('entity_message');
}

function entityScriptServerMessage(event) {
    console.log('entity script message ' + event.data);
    //entityscript_sendChannel.send('entity_script_message');
}

function messagesMixerMessage(event) {
    console.log('messages message ' + event.data);
    //messages_sendChannel.send('messages_message');
}

function assetServerMessage(event) {
    console.log('asset message ' + event.data);
    //asset_sendChannel.send('asset_message');
}

signalServer.onmessage = function (event) {
    if (event.data === 'connected')
    {
        pcConstraint = null;
        dataConstraint = null;
        console.log('Using SCTP based data channels');
        window.localConnection = localConnection = new RTCPeerConnection({
                                                                             iceServers: [{
                                                                                 urls: [
                                                                                   "stun:stun.l.google.com:19302",
                                                                                   "stun:stun1.l.google.com:19302",
                                                                                   "stun:stun2.l.google.com:19302",
                                                                                   "stun:stun3.l.google.com:19302",
                                                                                   "stun:stun4.l.google.com:19302"
                                                                           ]}]}, pcConstraint);
        console.log('Created local peer connection object localConnection');

        domain_sendChannel = localConnection.createDataChannel('domain_server_dc', dataConstraint);
        domain_sendChannel.onmessage = domainMessage;
        audio_sendChannel = localConnection.createDataChannel('audio_mixer_dc', dataConstraint);
        audio_sendChannel.onmessage = audioMixerMessage;
        avatar_sendChannel = localConnection.createDataChannel('avatar_mixer_dc', dataConstraint);
        avatar_sendChannel.onmessage = avatarMixerMessage;
        entity_sendChannel = localConnection.createDataChannel('entity_server_dc', dataConstraint);
        entity_sendChannel.onmessage = entityServerMessage;
        entityscript_sendChannel = localConnection.createDataChannel('entity_script_server_dc', dataConstraint);
        entityscript_sendChannel.onmessage = entityScriptServerMessage;
        messages_sendChannel = localConnection.createDataChannel('messages_mixer_dc', dataConstraint);
        messages_sendChannel.onmessage = messagesMixerMessage;
        asset_sendChannel = localConnection.createDataChannel('asset_server_dc', dataConstraint);
        asset_sendChannel.onmessage = assetServerMessage;

        console.log('Created send data channel');

        localConnection.onicecandidate = iceCallback;

        localConnection.createOffer().then(
            gotDescription,
            null
        );

        return;
    }

    var msg = JSON.parse(event.data);
    console.log("message");

    switch (msg.type) {
        case 'candidate':
            if (msg.candidate) {
                if (!have_answer) {
                    remoteCandidates.push(msg.candidate);
                } else {
                    console.log("candidate");
                    localConnection.addIceCandidate(new RTCIceCandidate(msg.candidate));
                }
            }
            break;
        case 'answer':
            console.log("answer");
            localConnection.setRemoteDescription(new RTCSessionDescription(msg))
            .then(function () {
              have_answer = true;
              var i = 0;
              for (i = 0; i < remoteCandidates.length; i++) {
                  localConnection.addIceCandidate(new RTCIceCandidate(remoteCandidates[i]));
              }
            });
            break;
        default:
            console.log("unknown websocket message type");
            break;
    }
};
