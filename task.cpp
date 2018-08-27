#include "task.h"

Task::Task(QObject * parent) :
    QObject(parent),
    client_address(QHostAddress::LocalHost),
    client_port(8000),
    server_address(QHostAddress::LocalHost),
    server_port(8001)
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
    client_socket->bind(QHostAddress::LocalHost, 8000);

    //setup hifi server socket for sending
    server_socket = new QUdpSocket(this);

    connect(client_socket, SIGNAL(readyRead()), this, SLOT(readPendingDatagrams()));
    // Application runs indefinitely (until terminated - e.g. Ctrl+C)
    //    emit finished();
}

void Task::readPendingDatagrams()
{
    //Event loop calls this function each time client socket is ready for reading
    qDebug() << "Task::readPendingDatagrams()";

    while (client_socket->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(client_socket->pendingDatagramSize());
        QHostAddress sender;
        quint16 senderPort;

        client_socket->readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);

        //Output debug information (for debug builds, not for production release)
        qDebug() << " read packet from " << sender << ":" << senderPort << " of size " << datagram.size() << " bytes";

        server_socket->writeDatagram(datagram, server_address, server_port);
    }
}
