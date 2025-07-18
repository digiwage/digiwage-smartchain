dnl Copyright (c) 2013-2016 The Bitcoin Core developers
dnl Distributed under the MIT software license, see the accompanying
dnl file COPYING or http://www.opensource.org/licenses/mit-license.php.

dnl Helper for cases where a Qt dependency is not met.
dnl Output: If Qt version is auto, set bitcoin_enable_qt to false. Else, exit.
AC_DEFUN([BITCOIN_QT_FAIL],[
  if test "x$bitcoin_qt_want_version" = xauto && test "x$bitcoin_qt_force" != xyes; then
    if test "x$bitcoin_enable_qt" != xno; then
      AC_MSG_WARN([$1; digiwage-qt frontend will not be built])
    fi
    bitcoin_enable_qt=no
    bitcoin_enable_qt_test=no
  else
    AC_MSG_ERROR([$1])
  fi
])

AC_DEFUN([BITCOIN_QT_CHECK],[
  if test "x$bitcoin_enable_qt" != xno && test "x$bitcoin_qt_want_version" != xno; then
    true
    $1
  else
    true
    $2
  fi
])

dnl BITCOIN_QT_PATH_PROGS([FOO], [foo foo2], [/path/to/search/first], [continue if missing])
dnl Helper for finding the path of programs needed for Qt.
dnl Inputs: $1: Variable to be set
dnl Inputs: $2: List of programs to search for
dnl Inputs: $3: Look for $2 here before $PATH
dnl Inputs: $4: If "yes", don't fail if $2 is not found.
dnl Output: $1 is set to the path of $2 if found. $2 are searched in order.
AC_DEFUN([BITCOIN_QT_PATH_PROGS],[
  BITCOIN_QT_CHECK([
    if test "x$3" != x; then
      AC_PATH_PROGS($1,$2,,$3)
    else
      AC_PATH_PROGS($1,$2)
    fi
    if test "x$$1" = x && test "x$4" != xyes; then
      BITCOIN_QT_FAIL([$1 not found])
    fi
  ])
])

dnl Initialize Qt input.
dnl This must be called before any other BITCOIN_QT* macros to ensure that
dnl input variables are set correctly.
dnl CAUTION: Do not use this inside of a conditional.
AC_DEFUN([BITCOIN_QT_INIT],[
  dnl enable Qt support
  AC_ARG_WITH([gui],
    [AS_HELP_STRING([--with-gui@<:@=no|qt5|auto@:>@],
    [build digiwage-qt GUI (default=auto)])],
    [
     bitcoin_qt_want_version=$withval
     if test "x$bitcoin_qt_want_version" = xyes; then
       bitcoin_qt_force=yes
       bitcoin_qt_want_version=auto
     fi
    ],
    [bitcoin_qt_want_version=auto])

  AC_ARG_WITH([qt-incdir],[AS_HELP_STRING([--with-qt-incdir=INC_DIR],[specify Qt include path (overridden by pkgconfig)])], [qt_include_path=$withval], [])
  AC_ARG_WITH([qt-libdir],[AS_HELP_STRING([--with-qt-libdir=LIB_DIR],[specify Qt lib path (overridden by pkgconfig)])], [qt_lib_path=$withval], [])
  AC_ARG_WITH([qt-plugindir],[AS_HELP_STRING([--with-qt-plugindir=PLUGIN_DIR],[specify Qt plugin path (overridden by pkgconfig)])], [qt_plugin_path=$withval], [])
  AC_ARG_WITH([qt-translationdir],[AS_HELP_STRING([--with-qt-translationdir=PLUGIN_DIR],[specify Qt translation path (overridden by pkgconfig)])], [qt_translation_path=$withval], [])
  AC_ARG_WITH([qt-svgdir],[AS_HELP_STRING([--with-qt-svgdir=PLUGIN_DIR],[specify Qt svg path (overridden by pkgconfig)])], [qt_svg_path=$withval], [])
  AC_ARG_WITH([qt-bindir],[AS_HELP_STRING([--with-qt-bindir=BIN_DIR],[specify Qt bin path])], [qt_bin_path=$withval], [])

  AC_ARG_WITH([qtdbus],
    [AS_HELP_STRING([--with-qtdbus],
    [enable DBus support (default is yes if Qt is enabled and QtDBus is found)])],
    [use_dbus=$withval],
    [use_dbus=auto])

  AC_SUBST(QT_TRANSLATION_DIR,$qt_translation_path)
])

dnl Find the appropriate version of Qt libraries and includes.
dnl Inputs: $1: Whether or not pkg-config should be used. yes|no. Default: yes.
dnl Outputs: See _BITCOIN_QT_FIND_LIBS_*
dnl Outputs: Sets variables for all Qt-related tools.
dnl Outputs: bitcoin_enable_qt, bitcoin_enable_qt_dbus, bitcoin_enable_qt_test
AC_DEFUN([BITCOIN_QT_CONFIGURE],[
  use_pkgconfig=$1

  if test "x$use_pkgconfig" = x; then
    use_pkgconfig=yes
  fi

  if test "x$use_pkgconfig" = xyes; then
    BITCOIN_QT_CHECK([_BITCOIN_QT_FIND_LIBS_WITH_PKGCONFIG])
  else
    BITCOIN_QT_CHECK([_BITCOIN_QT_FIND_LIBS_WITHOUT_PKGCONFIG])
  fi

  BITCOIN_QT_CHECK([
    if test "x$bitcoin_cv_qt_minimumrequired" != xyes; then
      BITCOIN_QT_FAIL([Qt version not supported])
    fi
  ])

  dnl This is ugly and complicated. Yuck. Works as follows:
  dnl For Qt5, we can check a header to find out whether Qt is build
  dnl statically. When Qt is built statically, some plugins must be linked into
  dnl the final binary as well.
  dnl With Qt5, languages moved into core and the WindowsIntegration plugin was
  dnl added.
  dnl _BITCOIN_QT_CHECK_STATIC_PLUGINS does a quick link-check and appends the
  dnl results to QT_LIBS.
  BITCOIN_QT_CHECK([
  TEMP_CPPFLAGS=$CPPFLAGS
  TEMP_CXXFLAGS=$CXXFLAGS
  CPPFLAGS="$QT_INCLUDES $QT_SVG_INCLUDES $CPPFLAGS"
  CXXFLAGS="$PIC_FLAGS $CXXFLAGS"
  _BITCOIN_QT_IS_STATIC
  if test "x$bitcoin_cv_static_qt" = xyes; then
    _BITCOIN_QT_FIND_STATIC_PLUGINS
    AC_DEFINE(QT_STATICPLUGIN, 1, [Define this symbol if Qt plugins are static])
    _BITCOIN_QT_CHECK_STATIC_PLUGINS([Q_IMPORT_PLUGIN(QMinimalIntegrationPlugin)],[-lqminimal])
    AC_DEFINE(QT_QPA_PLATFORM_MINIMAL, 1, [Define this symbol if the minimal Qt platform exists])
    _BITCOIN_QT_CHECK_STATIC_PLUGINS([Q_IMPORT_PLUGIN(QSvgPlugin)],[-lqsvg])
    _BITCOIN_QT_CHECK_STATIC_PLUGINS([Q_IMPORT_PLUGIN(QSvgIconPlugin)],[-lqsvgicon])
    if test "x$TARGET_OS" = xwindows; then
      _BITCOIN_QT_CHECK_STATIC_PLUGINS([Q_IMPORT_PLUGIN(QWindowsIntegrationPlugin)],[-lqwindows])
      AC_DEFINE(QT_QPA_PLATFORM_WINDOWS, 1, [Define this symbol if the Qt platform is Windows])
    elif test "x$TARGET_OS" = xlinux; then
      _BITCOIN_QT_CHECK_STATIC_PLUGINS([Q_IMPORT_PLUGIN(QXcbIntegrationPlugin)],[-lqxcb -lxcb-static])
      AC_DEFINE(QT_QPA_PLATFORM_XCB, 1, [Define this symbol if the Qt platform is XCB])
    elif test "x$TARGET_OS" = xdarwin; then
      AX_CHECK_LINK_FLAG([[-framework IOKit]],[QT_LIBS="$QT_LIBS -framework IOKit"],[AC_MSG_ERROR(could not iokit framework)])
      _BITCOIN_QT_CHECK_STATIC_PLUGINS([Q_IMPORT_PLUGIN(QCocoaIntegrationPlugin)],[-lqcocoa])
      AC_DEFINE(QT_QPA_PLATFORM_COCOA, 1, [Define this symbol if the Qt platform is Cocoa])
    fi
  fi
  CPPFLAGS=$TEMP_CPPFLAGS
  CXXFLAGS=$TEMP_CXXFLAGS
  ])

  if test "x$use_pkgconfig$qt_bin_path" = xyes; then
    qt_bin_path="`$PKG_CONFIG --variable=host_bins Qt5Core 2>/dev/null`"
  fi

  if test "x$use_hardening" != xno; then
    BITCOIN_QT_CHECK([
    AC_MSG_CHECKING([whether -fPIE can be used with this Qt config])
    TEMP_CPPFLAGS=$CPPFLAGS
    TEMP_CXXFLAGS=$CXXFLAGS
    CPPFLAGS="$QT_INCLUDES $CPPFLAGS"
    CXXFLAGS="$PIE_FLAGS $CXXFLAGS"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
        #include <QtCore/qconfig.h>
        #ifndef QT_VERSION
        #  include <QtCore/qglobal.h>
        #endif
      ]],
      [[
        #if defined(QT_REDUCE_RELOCATIONS)
        choke
        #endif
      ]])],
      [ AC_MSG_RESULT(yes); QT_PIE_FLAGS=$PIE_FLAGS ],
      [ AC_MSG_RESULT(no); QT_PIE_FLAGS=$PIC_FLAGS]
    )
    CPPFLAGS=$TEMP_CPPFLAGS
    CXXFLAGS=$TEMP_CXXFLAGS
    ])
  else
    BITCOIN_QT_CHECK([
    AC_MSG_CHECKING([whether -fPIC is needed with this Qt config])
    TEMP_CPPFLAGS=$CPPFLAGS
    CPPFLAGS="$QT_INCLUDES $CPPFLAGS"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
        #include <QtCore/qconfig.h>
        #ifndef QT_VERSION
        #  include <QtCore/qglobal.h>
        #endif
      ]],
      [[
        #if defined(QT_REDUCE_RELOCATIONS)
        choke
        #endif
      ]])],
      [ AC_MSG_RESULT(no)],
      [ AC_MSG_RESULT(yes); QT_PIE_FLAGS=$PIC_FLAGS]
    )
    CPPFLAGS=$TEMP_CPPFLAGS
    ])
  fi

  BITCOIN_QT_PATH_PROGS([MOC], [moc-qt5 moc5 moc], $qt_bin_path)
  BITCOIN_QT_PATH_PROGS([UIC], [uic-qt5 uic5 uic], $qt_bin_path)
  BITCOIN_QT_PATH_PROGS([RCC], [rcc-qt5 rcc5 rcc], $qt_bin_path)
  BITCOIN_QT_PATH_PROGS([LRELEASE], [lrelease-qt5 lrelease5 lrelease], $qt_bin_path)
  BITCOIN_QT_PATH_PROGS([LUPDATE], [lupdate-qt5 lupdate5 lupdate],$qt_bin_path, yes)

  MOC_DEFS='-DHAVE_CONFIG_H -I$(srcdir)'
  case $host in
    *darwin*)
     BITCOIN_QT_CHECK([
       MOC_DEFS="${MOC_DEFS} -DQ_OS_MAC"
       base_frameworks="-framework Foundation -framework ApplicationServices -framework AppKit"
       AX_CHECK_LINK_FLAG([[$base_frameworks]],[QT_LIBS="$QT_LIBS $base_frameworks"],[AC_MSG_ERROR([could not find base frameworks])])
     ])
    ;;
    *mingw*)
       BITCOIN_QT_CHECK([
         AX_CHECK_LINK_FLAG([[-mwindows]],[QT_LDFLAGS="$QT_LDFLAGS -mwindows"],[AC_MSG_WARN([-mwindows linker support not detected])])
       ])
  esac

  dnl enable Qt support
  AC_MSG_CHECKING([whether to build ]AC_PACKAGE_NAME[ GUI])
  BITCOIN_QT_CHECK([
    bitcoin_enable_qt=yes
    bitcoin_enable_qt_test=yes
    if test "x$have_qt_test" = xno; then
      bitcoin_enable_qt_test=no
    fi
    bitcoin_enable_qt_dbus=no
    if test "x$use_dbus" != xno && test "x$have_qt_dbus" = xyes; then
      bitcoin_enable_qt_dbus=yes
    fi
    if test "x$use_dbus" = xyes && test "x$have_qt_dbus" = xno; then
      AC_MSG_ERROR([libQtDBus not found. Install libQtDBus or remove --with-qtdbus.])
    fi
    if test "x$LUPDATE" = x; then
      AC_MSG_WARN([lupdate is required to update Qt translations])
    fi
  ],[
    bitcoin_enable_qt=no
  ])
  AC_MSG_RESULT([$bitcoin_enable_qt (Qt5)])

  AC_SUBST(QT_PIE_FLAGS)
  AC_SUBST(QT_INCLUDES)
  AC_SUBST(QT_LIBS)
  AC_SUBST(QT_LDFLAGS)
  AC_SUBST(QT_SVG_INCLUDES)
  AC_SUBST(QT_SVG_LIBS)
  AC_SUBST(QT_DBUS_INCLUDES)
  AC_SUBST(QT_DBUS_LIBS)
  AC_SUBST(QT_TEST_INCLUDES)
  AC_SUBST(QT_TEST_LIBS)
  AC_SUBST(QT_SELECT, qt5)
  AC_SUBST(MOC_DEFS)
])

dnl All macros below are internal and should _not_ be used from the main
dnl configure.ac.
dnl ----

dnl Internal. Check the included version of Qt against the passed minimum one.
dnl _BITCOIN_QT_VERSIONCHECK_PROGRAM([VERSION-MAJOR-NUMBER], [VERSION-MINOR-NUMBER], [VERSION-PATCH-NUMBER])
dnl Requires: INCLUDES must be populated as necessary.
m4_define([_BITCOIN_QT_VERSIONCHECK_PROGRAM],[
  AC_LANG_PROGRAM([[
    #include <QtGlobal>
  ]],[[
    #if (QT_VERSION < QT_VERSION_CHECK($1, $2, $3))
    choke
    #endif
  ]])
])

dnl Internal. Check included version of Qt against minimum specified in doc/dependencies.md
dnl Requires: INCLUDES must be populated as necessary.
dnl Output: bitcoin_cv_qt_minimumrequired=yes|no
AC_DEFUN([_BITCOIN_QT_CHECK_MINIMUM_REQUIRED],[
  AC_CACHE_CHECK([for Qt >= 5.5.1], bitcoin_cv_qt_minimumrequired,[
  AC_COMPILE_IFELSE([_BITCOIN_QT_VERSIONCHECK_PROGRAM(5,5,1)],
    [bitcoin_cv_qt_minimumrequired=yes],
    [bitcoin_cv_qt_minimumrequired=no])
])])

dnl Internal. Check if the included version of Qt is >= 5.8.
dnl Requires: INCLUDES must be populated as necessary.
dnl Output: bitcoin_cv_qt58=yes|no
AC_DEFUN([_BITCOIN_QT_CHECK_QT58],[
  AC_CACHE_CHECK([for Qt >= 5.8], bitcoin_cv_qt58,[
  AC_COMPILE_IFELSE([_BITCOIN_QT_VERSIONCHECK_PROGRAM(5,8,0)],
    [bitcoin_cv_qt58=yes],
    [bitcoin_cv_qt58=no])
])])


dnl Internal. Check if the linked version of Qt was built as static libs.
dnl Requires: Qt5.
dnl Requires: INCLUDES and LIBS must be populated as necessary.
dnl Output: bitcoin_cv_static_qt=yes|no
AC_DEFUN([_BITCOIN_QT_IS_STATIC],[
  AC_CACHE_CHECK([for static Qt], bitcoin_cv_static_qt,[
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
        #include <QtCore/qconfig.h>
        #ifndef QT_VERSION
        #  include <QtCore/qglobal.h>
        #endif
      ]],
      [[
        #if !defined(QT_STATIC)
        choke
        #endif
      ]])],
      [bitcoin_cv_static_qt=yes],
      [bitcoin_cv_static_qt=no])
    ])
])

dnl Internal. Check if the link-requirements for static plugins are met.
dnl Requires: INCLUDES and LIBS must be populated as necessary.
dnl Inputs: $1: A series of Q_IMPORT_PLUGIN().
dnl Inputs: $2: The libraries that resolve $1.
dnl Output: QT_LIBS is prepended or configure exits.
AC_DEFUN([_BITCOIN_QT_CHECK_STATIC_PLUGINS],[
  AC_MSG_CHECKING([for static Qt plugins: ]$2)
  CHECK_STATIC_PLUGINS_TEMP_LIBS="$LIBS"
  LIBS="$2 $QT_LIBS $LIBS"
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[
    #define QT_STATICPLUGIN
    #include <QtPlugin>
    $1]],
    [[return 0;]])],
    [AC_MSG_RESULT([yes]); QT_LIBS="$2 $QT_LIBS"],
    [AC_MSG_RESULT([no]); BITCOIN_QT_FAIL([Could not resolve: ]$2)])
  LIBS="$CHECK_STATIC_PLUGINS_TEMP_LIBS"
])

dnl Internal. Find paths necessary for linking Qt static plugins
dnl Inputs: qt_plugin_path. optional.
dnl Outputs: QT_LIBS is appended
AC_DEFUN([_BITCOIN_QT_FIND_STATIC_PLUGINS],[
    if test "x$qt_plugin_path" != x; then
      QT_LIBS="$QT_LIBS -L$qt_plugin_path/platforms -L$qt_plugin_path/imageformats -L$qt_plugin_path/iconengines"
      if test -d "$qt_plugin_path/accessible"; then
        QT_LIBS="$QT_LIBS -L$qt_plugin_path/accessible"
      fi
     if test "x$use_pkgconfig" = xyes; then
     : dnl
     m4_ifdef([PKG_CHECK_MODULES],[
       if test x$bitcoin_cv_qt58 = xno; then
         PKG_CHECK_MODULES([QTPLATFORM], [Qt5PlatformSupport], [QT_LIBS="$QTPLATFORM_LIBS $QT_LIBS"])
       else
         PKG_CHECK_MODULES([QTFONTDATABASE], [Qt5FontDatabaseSupport], [QT_LIBS="-lQt5FontDatabaseSupport $QT_LIBS"])
         PKG_CHECK_MODULES([QTEVENTDISPATCHER], [Qt5EventDispatcherSupport], [QT_LIBS="-lQt5EventDispatcherSupport $QT_LIBS"])
         PKG_CHECK_MODULES([QTTHEME], [Qt5ThemeSupport], [QT_LIBS="-lQt5ThemeSupport $QT_LIBS"])
         PKG_CHECK_MODULES([QTDEVICEDISCOVERY], [Qt5DeviceDiscoverySupport], [QT_LIBS="-lQt5DeviceDiscoverySupport $QT_LIBS"])
         PKG_CHECK_MODULES([QTACCESSIBILITY], [Qt5AccessibilitySupport], [QT_LIBS="-lQt5AccessibilitySupport $QT_LIBS"])
         PKG_CHECK_MODULES([QTFB], [Qt5FbSupport], [QT_LIBS="-lQt5FbSupport $QT_LIBS"])
                fi
       if test "x$TARGET_OS" = xlinux; then
         PKG_CHECK_MODULES([X11XCB], [x11-xcb], [QT_LIBS="$X11XCB_LIBS $QT_LIBS"])
         PKG_CHECK_MODULES([QTXCBQPA], [Qt5XcbQpa], [QT_LIBS="$QTXCBQPA_LIBS $QT_LIBS"])
       elif test "x$TARGET_OS" = xdarwin; then
         PKG_CHECK_MODULES([QTCLIPBOARD], [Qt5ClipboardSupport], [QT_LIBS="-lQt5ClipboardSupport $QT_LIBS"])
         PKG_CHECK_MODULES([QTGRAPHICS], [Qt5GraphicsSupport], [QT_LIBS="-lQt5GraphicsSupport $QT_LIBS"])
         PKG_CHECK_MODULES([QTCGL], [Qt5CglSupport], [QT_LIBS="-lQt5CglSupport $QT_LIBS"])
       fi
     ])
     else
       if test "x$TARGET_OS" = xwindows; then
         AC_CACHE_CHECK([for Qt >= 5.6], bitcoin_cv_need_platformsupport,[
           AC_COMPILE_IFELSE([_BITCOIN_QT_VERSIONCHECK_PROGRAM(5,6,0)],
           [bitcoin_cv_need_platformsupport=yes],
           [bitcoin_cv_need_platformsupport=no])
         ])
         if test "x$bitcoin_cv_need_platformsupport" = xyes; then
           if test x$bitcoin_cv_qt58 = xno; then
             BITCOIN_QT_CHECK(AC_CHECK_LIB([${QT_LIB_PREFIX}PlatformSupport],[main],,BITCOIN_QT_FAIL(lib$QT_LIB_PREFIXPlatformSupport not found)))
           else
             BITCOIN_QT_CHECK(AC_CHECK_LIB([${QT_LIB_PREFIX}FontDatabaseSupport],[main],,BITCOIN_QT_FAIL(lib$QT_LIB_PREFIXFontDatabaseSupport not found)))
             BITCOIN_QT_CHECK(AC_CHECK_LIB([${QT_LIB_PREFIX}EventDispatcherSupport],[main],,BITCOIN_QT_FAIL(lib$QT_LIB_PREFIXEventDispatcherSupport not found)))
             BITCOIN_QT_CHECK(AC_CHECK_LIB([${QT_LIB_PREFIX}ThemeSupport],[main],,BITCOIN_QT_FAIL(lib$QT_LIB_PREFIXThemeSupport not found)))
             BITCOIN_QT_CHECK(AC_CHECK_LIB([${QT_LIB_PREFIX}FbSupport],[main],,BITCOIN_QT_FAIL(lib$QT_LIB_PREFIXFbSupport not found)))
             BITCOIN_QT_CHECK(AC_CHECK_LIB([${QT_LIB_PREFIX}DeviceDiscoverySupport],[main],,BITCOIN_QT_FAIL(lib$QT_LIB_PREFIXDeviceDiscoverySupport not found)))
             BITCOIN_QT_CHECK(AC_CHECK_LIB([${QT_LIB_PREFIX}AccessibilitySupport],[main],,BITCOIN_QT_FAIL(lib$QT_LIB_PREFIXAccessibilitySupport not found)))
             QT_LIBS="$QT_LIBS -lversion -ldwmapi -luxtheme"
           fi
         fi
       fi
     fi
   fi
])

dnl Internal. Find Qt libraries using pkg-config.
dnl Outputs: All necessary QT_* variables are set.
dnl Outputs: have_qt_test and have_qt_dbus are set (if applicable) to yes|no.
AC_DEFUN([_BITCOIN_QT_FIND_LIBS_WITH_PKGCONFIG],[
  m4_ifdef([PKG_CHECK_MODULES],[
    QT_LIB_PREFIX=Qt5
    qt5_modules="Qt5Core Qt5Gui Qt5Network Qt5Widgets"
    BITCOIN_QT_CHECK([
      PKG_CHECK_MODULES([QT5], [$qt5_modules], [QT_INCLUDES="$QT5_CFLAGS"; QT_LIBS="$QT5_LIBS" have_qt=yes],[have_qt=no])

      if test "x$have_qt" != xyes; then
        have_qt=no
        BITCOIN_QT_FAIL([Qt dependencies not found])
      fi
    ])
    BITCOIN_QT_CHECK([
      PKG_CHECK_MODULES([QT_SVG], [${QT_LIB_PREFIX}Svg], [QT_SVG_INCLUDES="$QT_SVG_CFLAGS"; QT_LIBS="$QT_LIBS $QT_SVG_LIBS"],, BITCOIN_QT_FAIL([QtSvg not found]))
    ])
    BITCOIN_QT_CHECK([
      PKG_CHECK_MODULES([QT_CONCURRENT], [${QT_LIB_PREFIX}Concurrent], [QT_INCLUDES="$QT_INCLUDES $QT_CONCURRENT_CFLAGS"; QT_LIBS="$QT_LIBS $QT_CONCURRENT_LIBS"],, BITCOIN_QT_FAIL([QtConcurrent not found]))
    ])
    BITCOIN_QT_CHECK([
      PKG_CHECK_MODULES([QT_TEST], [${QT_LIB_PREFIX}Test], [QT_TEST_INCLUDES="$QT_TEST_CFLAGS"; have_qt_test=yes], [have_qt_test=no])
      if test "x$use_dbus" != xno; then
        PKG_CHECK_MODULES([QT_DBUS], [${QT_LIB_PREFIX}DBus], [QT_DBUS_INCLUDES="$QT_DBUS_CFLAGS"; have_qt_dbus=yes], [have_qt_dbus=no])
      fi
    ])
    BITCOIN_QT_CHECK([
      AC_CACHE_CHECK([for Qt >= 5.5.1], bitcoin_cv_qt_minimumrequired,
        PKG_CHECK_EXISTS(Qt5Core < 5.5.1, [bitcoin_cv_qt_minimumrequired=no], [bitcoin_cv_qt_minimumrequired=yes])
      )
    ])
    BITCOIN_QT_CHECK([
      AC_CACHE_CHECK([for Qt >= 5.8.0], bitcoin_cv_qt58,
        PKG_CHECK_EXISTS(Qt5Core < 5.8.0, [bitcoin_cv_qt58=no], [bitcoin_cv_qt58=yes])
      )
    ])
  ])
  true; dnl
])

dnl Internal. Find Qt libraries without using pkg-config. Version is deduced
dnl from the discovered headers.
dnl Inputs: bitcoin_qt_want_version (from --with-gui=). The version to use.
dnl         If "auto", the version will be discovered by _BITCOIN_QT_CHECK_MINIMUM_REQUIRED
dnl         and _BITCOIN_QT_CHECK_QT58.
dnl Outputs: All necessary QT_* variables are set.
dnl Outputs: have_qt_test and have_qt_dbus are set (if applicable) to yes|no.
AC_DEFUN([_BITCOIN_QT_FIND_LIBS_WITHOUT_PKGCONFIG],[
  TEMP_CPPFLAGS="$CPPFLAGS"
  TEMP_CXXFLAGS="$CXXFLAGS"
  CXXFLAGS="$PIC_FLAGS $CXXFLAGS"
  TEMP_LIBS="$LIBS"
  BITCOIN_QT_CHECK([
    if test "x$qt_include_path" != x; then
      QT_INCLUDES="-I$qt_include_path -I$qt_include_path/QtCore -I$qt_include_path/QtGui -I$qt_include_path/QtWidgets -I$qt_include_path/QtNetwork -I$qt_include_path/QtTest -I$qt_include_path/QtDBus -I$qt_include_path/QtConcurrent -I$qt_include_path/QtSvg -I$qt_include_path/QtCharts"
      CPPFLAGS="$QT_INCLUDES $CPPFLAGS"
    fi
  ])

  BITCOIN_QT_CHECK([AC_CHECK_HEADER([QtPlugin],,BITCOIN_QT_FAIL([QtCore headers missing]))])
  BITCOIN_QT_CHECK([AC_CHECK_HEADER([QApplication],, BITCOIN_QT_FAIL([QtGui headers missing]))])
  BITCOIN_QT_CHECK([AC_CHECK_HEADER([QLocalSocket],, BITCOIN_QT_FAIL([QtNetwork headers missing]))])
  BITCOIN_QT_CHECK([AC_CHECK_HEADER([QtConcurrent],, BITCOIN_QT_FAIL([QtConcurrent headers missing]))])

  BITCOIN_QT_CHECK([
    if test "x$bitcoin_qt_want_version" = xauto; then
      _BITCOIN_QT_CHECK_MINIMUM_REQUIRED
      _BITCOIN_QT_CHECK_QT58
    fi
    QT_LIB_PREFIX=Qt5
  ])

  BITCOIN_QT_CHECK([
    LIBS=
    if test "x$qt_lib_path" != x; then
      LIBS="$LIBS -L$qt_lib_path"
    fi

    if test "x$TARGET_OS" = xwindows; then
      AC_CHECK_LIB([imm32],      [main],, BITCOIN_QT_FAIL([libimm32 not found]))
    fi
  ])

  BITCOIN_QT_CHECK(AC_CHECK_LIB([z] ,[main],,AC_MSG_WARN([zlib not found. Assuming Qt has it built-in])))
  BITCOIN_QT_CHECK(AC_SEARCH_LIBS([jpeg_create_decompress] ,[qtjpeg jpeg],,AC_MSG_WARN([libjpeg not found. Assuming Qt has it built-in])))
  if test x$bitcoin_cv_qt58 = xno; then
    BITCOIN_QT_CHECK(AC_SEARCH_LIBS([png_error] ,[qtpng png],,AC_MSG_WARN([libpng not found. Assuming Qt has it built-in])))
    BITCOIN_QT_CHECK(AC_SEARCH_LIBS([pcre16_exec], [qtpcre pcre16],,AC_MSG_WARN([libpcre16 not found. Assuming Qt has it built-in])))
  else
    BITCOIN_QT_CHECK(AC_SEARCH_LIBS([png_error] ,[qtlibpng png],,AC_MSG_WARN([libpng not found. Assuming Qt has it built-in])))
    BITCOIN_QT_CHECK(AC_SEARCH_LIBS([pcre2_match_16], [qtpcre2 libqtpcre2],,AC_MSG_WARN([libqtpcre2 not found. Assuming Qt has it built-in])))
  fi
  BITCOIN_QT_CHECK(AC_SEARCH_LIBS([hb_ot_tags_from_script] ,[qtharfbuzzng qtharfbuzz harfbuzz],,AC_MSG_WARN([libharfbuzz not found. Assuming Qt has it built-in or support is disabled])))
  BITCOIN_QT_CHECK(AC_CHECK_LIB([${QT_LIB_PREFIX}Core]   ,[main],,BITCOIN_QT_FAIL(lib${QT_LIB_PREFIX}Core not found)))
  BITCOIN_QT_CHECK(AC_CHECK_LIB([${QT_LIB_PREFIX}Gui]    ,[main],,BITCOIN_QT_FAIL(lib${QT_LIB_PREFIX}Gui not found)))
  BITCOIN_QT_CHECK(AC_CHECK_LIB([${QT_LIB_PREFIX}Network],[main],,BITCOIN_QT_FAIL(lib${QT_LIB_PREFIX}Network not found)))
  BITCOIN_QT_CHECK(AC_CHECK_LIB([${QT_LIB_PREFIX}Widgets],[main],,BITCOIN_QT_FAIL(lib${QT_LIB_PREFIX}Widgets not found)))
  BITCOIN_QT_CHECK(AC_CHECK_LIB([${QT_LIB_PREFIX}Concurrent],[main],,BITCOIN_QT_FAIL(lib${QT_LIB_PREFIX}Concurrent not found)))
  QT_LIBS="$LIBS"
  LIBS="$TEMP_LIBS"

  BITCOIN_QT_CHECK([
    LIBS=
    if test "x$qt_lib_path" != x; then
      LIBS="-L$qt_lib_path"
    fi
    AC_CHECK_LIB([${QT_LIB_PREFIX}Svg],       [main],, BITCOIN_QT_FAIL(lib${QT_LIB_PREFIX}Svg not found))
    AC_CHECK_HEADER([QtSvg],, BITCOIN_QT_FAIL(lib${QT_LIB_PREFIX}Svg not found))
    QT_LIBS="$QT_LIBS $LIBS"
    QT_SVG_LIBS="$LIBS"
    LIBS=
    if test "x$qt_lib_path" != x; then
      LIBS="-L$qt_lib_path"
    fi
    AC_CHECK_LIB([${QT_LIB_PREFIX}Test],      [main],, have_qt_test=no)
    AC_CHECK_HEADER([QTest],, have_qt_test=no)
    QT_TEST_LIBS="$LIBS"
    if test "x$use_dbus" != xno; then
      LIBS=
      if test "x$qt_lib_path" != x; then
        LIBS="-L$qt_lib_path"
      fi
      AC_CHECK_LIB([${QT_LIB_PREFIX}DBus],      [main],, have_qt_dbus=no)
      AC_CHECK_HEADER([QtDBus],, have_qt_dbus=no)
      QT_DBUS_LIBS="$LIBS"
    fi
  ])
  CPPFLAGS="$TEMP_CPPFLAGS"
  CXXFLAGS="$TEMP_CXXFLAGS"
  LIBS="$TEMP_LIBS"
])
