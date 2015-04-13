AC_INIT([mod_proxy_msrpc], [0.1.1], [micha@lenk.info])

# Checks for programs.
AC_PROG_CC
AC_CHECK_PROGS([APXS], [apxs2 apxs], [])
if test -z "$APXS"; then
  AC_MSG_ERROR([could not find APXS])
fi
APXS_INCLUDES="`$APXS -q INCLUDEDIR 2> /dev/null`"

# Check for Apache version.
AC_MSG_CHECKING([for ap_socache.h in $APXS_INCLUDES]) 
if test -e [$APXS_INCLUDES/ap_socache.h]; then
  AC_MSG_RESULT([yes]) 
else
  AC_MSG_RESULT([no])
  AC_MSG_ERROR([ap_socache.h should be available with Apache httpd 2.4.0 or later.])
fi

# Check for libraries.
PKG_PROG_PKG_CONFIG
PKG_CHECK_MODULES([APR], [apr-1 >= 1.0])
PKG_CHECK_MODULES([APRUTIL], [apr-util-1])
PKG_CHECK_MODULES([CHECK], [check >= 0.9.4])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h limits.h stdlib.h string.h unistd.h sys/types.h sys/stat.h sys/inotify.h sys/select.h uuid/uuid.h],
  [], AC_MSG_ERROR([some of the required header files could not be found.]))

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_INT8_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MEMCMP
AC_CHECK_FUNCS([strcasecmp strchr strrchr inotify_init1])
AC_CHECK_LIB([uuid], [uuid_unparse], [UUIDLIB=-luuid], AC_MSG_ERROR([could not find libuuid]))
AC_SUBST([UUIDLIB])

AC_CONFIG_SRCDIR([src/mod_proxy_msrpc.c])
AC_CONFIG_FILES([Makefile src/Makefile test/Makefile])

AC_OUTPUT
