QT -= gui
QT += network

CONFIG += c++11 console
CONFIG -= app_bundle

QMAKE_MACOSX_DEPLOYMENT_TARGET=10.9

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += main.cpp \
    task.cpp \
    packet.cpp \
    utils.cpp \
    node.cpp \
    hmacauth.cpp \
    peerconnectionhandler.cpp

HEADERS += \
    task.h \
    packet.h \
    utils.h \
    node.h \
    hmacauth.h \
    portableendian.h \
    peerconnectionhandler.h

unix:macx:LIBS += -L"/usr/local/Cellar/openssl/1.0.2o_1/lib" -lssl -lcrypto
unix:macx:INCLUDEPATH += "/usr/local/Cellar/openssl/1.0.2o_1/include"
unix:macx:OPENSSL_LIBS='-L"/usr/local/Cellar/openssl/1.0.2o_1/lib" -lssl -lcrypto'
unix:macx:LIBS += -framework IOKit -framework CoreFoundation -framework Foundation -framework CoreAudio -framework CoreServices \
    -framework AudioUnit -framework AudioToolbox -framework CoreGraphics

INCLUDEPATH +="./resources/openssl/include"
win32:LIBS += -L"$$PWD/resources/openssl/x64/lib"
win32:LIBS += -llibcrypto -llibssl
win32:OPENSSL_LIBS ='-L"$$PWD/resources/openssl/x64/lib" -llibcrypto -llibssl'

INCLUDEPATH +="/Users/mccrae/Desktop/firebox/webrtc/src/third_party/abseil-cpp"
INCLUDEPATH +="/Users/mccrae/Desktop/firebox/webrtc/src"
macx:LIBS += -L"/Users/mccrae/Desktop/firebox/webrtc/src/out/Default/obj"
macx:LIBS += -lwebrtc
#INCLUDEPATH +="./resources/webrtc/include"
#win32:LIBS += -L"$$PWD/resources/webrtc/lib/x64/Release"
#win32:LIBS += -lwebrtc

win32:LIBS += -L"$$PWD/resources/windows"
win32:LIBS += -lws2_32 -lAdvAPI32

CONFIG += openssl-linked
CONFIG += no_keywords
