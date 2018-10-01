/*
 * HiFi_WebRTC_Relay
 *
 * A server-side console application that bridges WebRTC clients with HiFi servers.
 *
 * Code is licensed under Apache 2.0.
 *
 * Authors: Janus VR, Inc.
 *
 */

#include <QCoreApplication>
#include <QTimer>

#include "task.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    // Task parented to the application so that it
    // will be deleted by the application.
    Task * task = new Task(&a);

    // This will cause the application to exit when
    // the task signals finished.
    QObject::connect(task, SIGNAL(Finished()), &a, SLOT(quit()));

    task->ProcessCommandLineArguments(argc, argv);

    // This will run the task from the application event loop.
    QTimer::singleShot(0, task, SLOT(run()));

    return a.exec();
}
