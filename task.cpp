#include "task.h"

Task::Task(QObject * parent) :
    QObject(parent),
    client_address(QHostAddress::LocalHost),
    client_port(4444),
    server_address(QHostAddress::LocalHost),
    server_port(5555)
{
    qDebug() << "Task::Task()";
}

void Task::ProcessCommandLineArguments(int argc, char * argv[])
{
    for (int i=1; i<argc; ++i) {
        const QString s = QString(argv[i]).toLower();
        if (s.right(7) == "-server" && i+2 < argc) {
            server_address = QHostAddress(QString(argv[i+1]));
            server_port = QString(argv[i+2]).toInt();
            i+=2;
        }
        else if (s.right(7) == "-client" && i+2 < argc) {
            client_address = QHostAddress(QString(argv[i+1]));
            client_port = QString(argv[i+2]).toInt();
            i+=2;
        }
        else if (s.right(5) == "-help") {
            qDebug() << "Usage: \n hifi_webrtc_relay [-client address port] [-server address port] [-help]";

            // Just exit after displaying this help message
            exit(0);
        }
    }
}

void Task::run()
{
    // Do processing here
    qDebug() << "Task::run()";

    //setup client socket for receiving
    client_socket = new QUdpSocket(this);
    client_socket->bind(QHostAddress::LocalHost, 6666);

    //setup hifi server socket for sending
    server_socket = new QUdpSocket(this);
    server_socket->bind(QHostAddress::LocalHost, 7777);

    signal_mapper = new QSignalMapper(this);
    signal_mapper->setMapping(client_socket, QString("client"));
    signal_mapper->setMapping(server_socket, QString("server"));

    connect(client_socket, SIGNAL(readyRead()), signal_mapper, SLOT (map()));
    connect(server_socket, SIGNAL(readyRead()), signal_mapper, SLOT (map()));

    connect(signal_mapper, SIGNAL(mapped(QString)), this, SLOT(readPendingDatagrams(QString)));

    //QString test = "test";
    //client_socket->writeDatagram(test.toLatin1(), client_address, client_port);

    // Application runs indefinitely (until terminated - e.g. Ctrl+C)
    //    emit finished();
}

void Task::readPendingDatagrams(QString f)
{
    //Event loop calls this function each time client socket is ready for reading
    qDebug() << "Task::readPendingDatagrams()";

    QUdpSocket * from = (f == "client") ? client_socket : server_socket;
    QUdpSocket * to = (f == "client") ? server_socket : client_socket;
    QHostAddress address = (f == "client") ? server_address : client_address;
    quint16 port = (f == "client") ? server_port : client_port;

    while (from->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(from->pendingDatagramSize());
        QHostAddress sender;
        quint16 senderPort;

        from->readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);

        //Output debug information (for debug builds, not for production release)
        qDebug() << " read packet from " << sender << f << ":" << senderPort << " of size " << datagram.size() << " bytes";

        to->writeDatagram(datagram, address, port);
    }
}
