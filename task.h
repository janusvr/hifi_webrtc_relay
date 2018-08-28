#ifndef TASK_H
#define TASK_H

#include <QObject>
#include <QDebug>
#include <QString>
#include <QSignalMapper>
#include <QtNetwork/QUdpSocket>

class Task : public QObject
{
    Q_OBJECT

public:

    Task(QObject *parent = 0);
    void ProcessCommandLineArguments(int argc, char * argv[]);

public slots:

    void run();
    void readPendingDatagrams(QString f);

signals:

    void finished();

private:

    QSignalMapper * signal_mapper;

    QUdpSocket * client_socket;
    QHostAddress client_address;
    quint16 client_port;

    QUdpSocket * server_socket;
    QHostAddress server_address;
    quint16 server_port;

};
#endif // TASK_H
