// Copyright (c) 2011-2013 The Bitcoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "macdockiconhandler.h"

#include <QImageWriter>
#include <QMenu>
#include <QBuffer>
#include <QWidget>

#undef slots
#include <Cocoa/Cocoa.h>
#include <AppKit/AppKit.h>
#include <objc/runtime.h>

static MacDockIconHandler *s_instance = nullptr;

bool dockClickHandler(id self,SEL _cmd,...) {
    Q_UNUSED(self)
    Q_UNUSED(_cmd)

    s_instance->handleDockIconClickEvent();

    // Return NO (false) to suppress the default OS X actions
    return false;
}

void setupDockClickHandler() {
    Class cls = objc_getClass("NSApplication");
    Class delClass = (Class)[[[NSApplication sharedApplication] delegate] class];
    SEL shouldHandle = sel_registerName("applicationShouldHandleReopen:hasVisibleWindows:");
    if (class_getInstanceMethod(delClass, shouldHandle))
        class_replaceMethod(delClass, shouldHandle, (IMP)dockClickHandler, "B@:");
    else
        class_addMethod(delClass, shouldHandle, (IMP)dockClickHandler,"B@:");
}


MacDockIconHandler::MacDockIconHandler() : QObject()
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];

    setupDockClickHandler();
    this->m_dummyWidget = new QWidget();
    this->m_dockMenu = new QMenu(this->m_dummyWidget);
    this->setMainWindow(nullptr);
    this->m_dockMenu->setAsDockMenu();
    [pool release];
}

void MacDockIconHandler::setMainWindow(QMainWindow *window) {
    this->mainWindow = window;
}

MacDockIconHandler::~MacDockIconHandler()
{
    delete this->m_dummyWidget;
    this->setMainWindow(NULL);
}

QMenu *MacDockIconHandler::dockMenu()
{
    return this->m_dockMenu;
}

void MacDockIconHandler::setIcon(const QIcon &icon)
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    NSImage *image = nil;
    if (icon.isNull())
        image = [[NSImage imageNamed:@"NSApplicationIcon"] retain];
    else {
        // generate NSImage from QIcon and use this as dock icon.
        QSize size = icon.actualSize(QSize(128, 128));
        QPixmap pixmap = icon.pixmap(size);

        // Write image into a R/W buffer from raw pixmap, then save the image.
        QBuffer notificationBuffer;
        if (!pixmap.isNull() && notificationBuffer.open(QIODevice::ReadWrite)) {
            QImageWriter writer(&notificationBuffer, "PNG");
            if (writer.write(pixmap.toImage())) {
                NSData* macImgData = [NSData dataWithBytes:notificationBuffer.buffer().data()
                                                    length:notificationBuffer.buffer().size()];
                image =  [[NSImage alloc] initWithData:macImgData];
            }
        }

        if(!image) {
            // if testnet image could not be created, load std. app icon
            image = [[NSImage imageNamed:@"NSApplicationIcon"] retain];
        }
    }

    [NSApp setApplicationIconImage:image];
    [image release];
    [pool release];
}

MacDockIconHandler *MacDockIconHandler::instance()
{
    if (!s_instance)
        s_instance = new MacDockIconHandler();
    return s_instance;
}

void MacDockIconHandler::cleanup()
{
    delete s_instance;
}

void MacDockIconHandler::handleDockIconClickEvent()
{
    if (this->mainWindow)
    {
        this->mainWindow->activateWindow();
        this->mainWindow->show();
    }

    Q_EMIT this->dockIconClicked();
}
/**
 * Force application activation on macOS. With Qt 5.5.1 this is required when
 * an action in the Dock menu is triggered.
 * TODO: Define a Qt version where it's no-longer necessary.
 */
void ForceActivation()
{
    [[NSApplication sharedApplication] activateIgnoringOtherApps:YES];
}