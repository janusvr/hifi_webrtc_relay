#include "task.h"

Task::Task(QObject * parent) :
    QObject(parent),
    signaling_server_port(8118)
{
    Utils::SetupTimestamp();
    Utils::SetupProtocolVersionSignature();

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
        hifi_connections[i]->Stop();
        delete hifi_connections[i];
    }
    signaling_server->close();
}

void Task::ProcessCommandLineArguments(int argc, char * argv[])
{
    for (int i=1; i<argc; ++i) {
        const QString s = QString(argv[i]).toLower();
        if (s.right(7) == "-iceserver" && i+2 < argc) {
            Utils::SetDefaultIceServerAddress(QHostAddress(QString(argv[i+1])));
            Utils::SetDefaultIceServerPort(QString(argv[i+2]).toInt());
            i+=2;
        }
        else if (s.right(5) == "-help") {
            qDebug() << "Usage: \n hifi_webrtc_relay [-iceserver address port] [-help]";

            // Just exit after displaying this help message
            exit(0);
        }
    }
}

void Task::run()
{
    qDebug() << "Task::run() - Started HiFi WebRTC Relay";

    // Application runs indefinitely (until terminated - e.g. Ctrl+C)
    //    Q_EMIT finished();
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
        qDebug() << "Task::DisconnectHifiConnection()" << s;
        s->Stop();
        delete s;
    }
}
