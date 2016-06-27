# - Try to find JsonGlib-1.0
# Once done, this will define
#
#  JsonGlib_FOUND - system has Glib
#  JsonGlib_INCLUDE_DIRS - the Glib include directories
#  JsonGlib_LIBRARIES - link these to use Glib

find_package(PkgConfig)
pkg_check_modules(PC_JSONGLIB REQUIRED QUIET json-glib-1.0)

find_path(JSONGLIB_INCLUDE_DIRS
        NAMES json-glib/json-glib.h
        HINTS ${PC_JSONGLIB_INCLUDEDIR}
        ${PC_JSONGLIB_INCLUDE_DIRS}
#        PATH_SUFFIXES json-glib-1.0
        )

find_library(JSONGLIB_LIBRARIES
        NAMES json-glib-1.0
        HINTS ${PC_JSONGLIB_LIBDIR}
        ${PC_JSONGLIB_LIBRARY_DIRS}
        )

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(JsonLib REQUIRED_VARS JSONGLIB_INCLUDE_DIRS JSONGLIB_LIBRARIES
        VERSION_VAR   PC_JSONGLIB_VERSION)

mark_as_advanced(
        JSONGLIB_INCLUDE_DIRS
        JSONGLIB_LIBRARIES
)

