var signalServer = new WebSocket('ws://localhost:8118');
var datachannel;
var remoteCandidates = [];
var have_answer = false;
var id;

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

function relayMessage(event) {
    console.log('relay message ' + event.data + '\n');
    //datachannel.send(event.data);
}

signalServer.onmessage = function (event) {

    var msg = JSON.parse(event.data);
    console.log("message");

    switch (msg.type) {
        case 'connected':
            //Send Domain Name to relay for lookup
            var m ={
                type: 'domain',
                domain_name: 'hifi://janusvr'
            };
            signalServer.send(JSON.stringify(m));

            id = msg.id;
            console.log('node id ' + id);

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

            datachannel = localConnection.createDataChannel('datachannel', dataConstraint);
            datachannel.onmessage = relayMessage;

            console.log('Created send data channel');

            localConnection.onicecandidate = iceCallback;

            localConnection.createOffer().then(
                gotDescription,
                null
            );

            break;
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
