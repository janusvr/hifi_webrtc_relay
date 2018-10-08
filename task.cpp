#include "task.h"

Task::Task(QObject * parent) :
    QObject(parent),
    signaling_server_port(8118)
{
    Utils::SetupTimestamp();
    Utils::SetupProtocolVersionSignature();

    qDebug() << "Task::Task() - Synchronously looking up IP address for hostname" << Utils::GetStunServerHostname();
    QHostInfo result_stun = QHostInfo::fromName(Utils::GetStunServerHostname());
    HandleLookupResult(result_stun, "stun");
    qDebug() << "Task::Task() - STUN server IP address: " << Utils::GetStunServerHostname();

    qDebug() << "Task::Task() - Synchronously looking up IP address for hostname" << Utils::GetIceServerHostname();
    QHostInfo result_ice = QHostInfo::fromName(Utils::GetIceServerHostname());
    HandleLookupResult(result_ice, "ice");
    qDebug() << "Task::Task() - ICE server IP address: " << Utils::GetIceServerHostname();

    signaling_server = new QWebSocketServer(QStringLiteral("Signaling Server"), QWebSocketServer::NonSecureMode, this);

    if (signaling_server->listen(QHostAddress::Any, signaling_server_port)) {
        connect(signaling_server, &QWebSocketServer::newConnection, this, &Task::Connect);
        connect(signaling_server, &QWebSocketServer::closed, this, &Task::Disconnect);
    }
}

Task::~Task()
{
    for (int i = 0; i < hifi_connections.size(); i++)
    {
        delete hifi_connections[i];
    }
    signaling_server->close();
}

void Task::ProcessCommandLineArguments(int argc, char * argv[])
{
    for (int i=1; i<argc; ++i) {
        const QString s = QString(argv[i]).toLower();
        if (s.right(7) == "-iceserver" && i+2 < argc) {
            Utils::SetUseCustomIceServer(true);
            Utils::SetIceServerAddress(QHostAddress(QString(argv[i+1])));
            Utils::SetIceServerPort(QString(argv[i+2]).toInt());
            i+=2;
        }
        else if (s.right(7) == "-domain" && i+1 < argc) {
            QString d(argv[i+1]);
            if (d.left(7) == "hifi://"){
                Utils::SetDomainName(d.remove("hifi://"));
            }
            else{
                Utils::SetDomainName(d);
            }
            i+=2;
        }
        else if (s.right(5) == "-help") {
            qDebug() << "Usage: \n hifi_webrtc_relay [-iceserver address port] [-domain placename] [-help]";

            // Just exit after displaying this help message
            exit(0);
        }
    }
}

void Task::run()
{
    qDebug() << "Task::run() - Started HiFi WebRTC Relay";

    // Domain ID lookup
    QNetworkAccessManager * nam = new QNetworkAccessManager(this);
    QNetworkRequest request("https://metaverse.highfidelity.com/api/v1/places/" + Utils::GetDomainName());
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    domain_reply = nam->get(request);
    connect(domain_reply, SIGNAL(finished()), this, SLOT(DomainRequestFinished()));

    // Application runs indefinitely (until terminated - e.g. Ctrl+C)
    //    Q_EMIT finished();
}

void Task::HandleLookupResult(const QHostInfo& hostInfo, QString addr_type)
{
    if (hostInfo.error() != QHostInfo::NoError) {
        qDebug() << "Task::handleLookupResult() - Lookup failed for" << hostInfo.lookupId() << ":" << hostInfo.errorString();
    } else {
        for (int i = 0; i < hostInfo.addresses().size(); i++) {
            // just take the first IPv4 address
            QHostAddress address = hostInfo.addresses()[i];
            if (address.protocol() == QAbstractSocket::IPv4Protocol) {

                if (addr_type == "stun") Utils::SetStunServerAddress(address);
                else if (addr_type == "ice") Utils::SetIceServerAddress(address);

                qDebug() << "Task::handleLookupResult() - QHostInfo lookup result for"
                    << hostInfo.hostName() << "with lookup ID" << hostInfo.lookupId() << "is" << address.toString();
                break;
            }
        }
    }
}

void Task::DomainRequestFinished()
{
    if (domain_reply) {
        if (domain_reply->error() == QNetworkReply::NoError && domain_reply->isOpen()) {
            domain_reply_contents += domain_reply->readAll();

            //qDebug() << domain_reply_contents;

            QJsonDocument doc;
            doc = QJsonDocument::fromJson(domain_reply_contents);
            QJsonObject obj = doc.object();
            QJsonObject data = obj["data"].toObject();
            QJsonObject place = data["place"].toObject();
            QJsonObject domain = place["domain"].toObject();
            QUuid domain_id = QUuid(domain["id"].toString());
            Utils::SetDomainID(domain_id);
            QString domain_place_name = domain["default_place_name"].toString();
            Utils::SetDomainPlaceName(domain_place_name);

            if (domain.contains("ice_server_address")) {
                QHostAddress ice_server_address = QHostAddress(domain["ice_server_address"].toString());
                Utils::SetIceServerAddress(ice_server_address);
                bool use_custom_ice_server = true;
                Utils::SetUseCustomIceServer(use_custom_ice_server);
            }
        }
        domain_reply->close();
    }

    qDebug() << "Task::domainRequestFinished() - Domain name" << Utils::GetDomainName();
    qDebug() << "Task::domainRequestFinished() - Domain place name" << Utils::GetDomainPlaceName();
    qDebug() << "Task::domainRequestFinished() - Domain ID" << Utils::GetDomainID();

    Utils::SetFinishedDomainIDRequest(true);
}

void Task::Connect()
{
    QWebSocket *s = signaling_server->nextPendingConnection();

    HifiConnection * h = new HifiConnection(s);
    connect(h, SIGNAL(Disconnected()), this, SLOT(DisconnectHifiConnection()));
    hifi_connections.push_back(h);
}

void Task::Disconnect()
{

}

void Task::ServerConnected()
{
    //qDebug() << "Task::ServerConnected()";
}

void Task::ServerDisconnected()
{
    //qDebug() << "Task::ServerDisconnected()";
}

void Task::DisconnectHifiConnection()
{
    HifiConnection *s = qobject_cast<HifiConnection *>(sender());
    if (hifi_connections.contains(s)) {
        hifi_connections.removeAll(s);
        qDebug () << "Task::DisconnectHifiConnection()" << s;
        delete s;
    }
}
