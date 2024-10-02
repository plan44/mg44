// Copyright (c) 2013-2022 plan44.ch / Lukas Zeller, Zurich, Switzerland
//
// Based on mongoose sample code Copyright (c) 2004-2013 Sergey Lyubka
// Using mongoose branch civetweb Copyright (c) 2013-2020 the Civetweb developers
//   with additions (c) 2013-2022 plan44.ch / Lukas Zeller
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif

#define _XOPEN_SOURCE 600  // For PATH_MAX on linux

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>

#include "civetweb.h"

#include <sys/wait.h>
#include <unistd.h>
#include <sys/param.h>

// unix I/O and network
#include <sys/types.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include <time.h>
#include <pthread.h>

#define DIRSEP '/'

#define MAX_OPTIONS 40
#define MAX_CONF_FILE_LINE_SIZE (8 * 1024)

#define MAX_UPLOAD_PATH_LENGTH 100


static int exit_flag;
static char server_name[40];        // Set by init_server_name()
static char config_file[PATH_MAX];  // Set by process_command_line_arguments()
static struct mg_context *ctx;      // Set by start_mongoose()

static char csrf_token_seed[9];     // random string for this server instance
static char lastUploadedFilePath[MAX_UPLOAD_PATH_LENGTH]; // path to last file uploaded


#ifdef __APPLE__
#define MAX_API_OPT_CHARS 400
#else
#define MAX_API_OPT_CHARS 40
#endif
#define MAX_LONG_OPT_CHARS 255
// JSON CSRF protection
static char jsonCSRFPath[MAX_API_OPT_CHARS]; // path prefix for JSON CSRF token generator
static char noCSRFPaths[MAX_LONG_OPT_CHARS]; // (colon separated) paths that do not need CSRF checking
// JSON REST API passtrough
static char jsonApiPath[MAX_API_OPT_CHARS]; // path prefix for JSON API passthrough
static char jsonApiHost[MAX_API_OPT_CHARS]; // host name/IP for JSON API passthrough
static char jsonApiService[MAX_API_OPT_CHARS]; // service name or port number for JSON API pass through
static char jsonApiUploadPath[MAX_API_OPT_CHARS]; // path prefix for JSON API cal with preceeding file upload
// JSON command line API passtrough
static char jsonCmdlinePath[MAX_API_OPT_CHARS]; // path prefix for JSON command line passthrough
static char jsonCmdlineTool[MAX_API_OPT_CHARS]; // full path for command line tool which handles JSON requests
static char jsonUploadPath[MAX_API_OPT_CHARS]; // path prefix for JSON command with preceeding file upload
static char uploadDir[MAX_API_OPT_CHARS]; // directory where to save uploaded files
// extra auth
static char extraAuth[MAX_LONG_OPT_CHARS]; // path:path*:path=authfile[,path=authfile] extra auth specifications. path* means all path starting as specified

#if !defined(CONFIG_FILE)
#define CONFIG_FILE "mongoose.conf"
#endif /* !CONFIG_FILE */

static void signal_handler(int sig_num) {
  exit_flag = sig_num;
}

static void die(const char *fmt, ...) {
  va_list ap;
  char msg[200];

  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);

  fprintf(stderr, "%s\n", msg);

  exit(EXIT_FAILURE);
}


static void show_version(void) {
  fprintf(stderr, "mg44 v%s based on civetweb %s\n",
    #if defined(P44_APPLICATION_VERSION)
    P44_APPLICATION_VERSION, // explicit application version override
    #elif defined(PACKAGE_VERSION)
    PACKAGE_VERSION, // automake package version number
    #else
    "????", // none known
    #endif
    mg_version()
  );
}


static void show_usage_and_exit(void) {
  const char **names;
  int i;

  show_version();
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  mg44 -A <htpasswd_file> <realm> <user> <passwd> # edit password file\n");
  fprintf(stderr, "  mg44 -D <method> <host> <doc> [<contenttype> <body>] # https test\n");
  fprintf(stderr, "  mg44 -V # show version\n");
  fprintf(stderr, "  mg44 [config_file] # start server\n");
  fprintf(stderr, "  mg44 [-option value ...] # start server\n");
  fprintf(stderr, "\nOPTIONS:\n");

  names = mg_get_valid_option_names();
  for (i = 0; names[i] != NULL; i += 2) {
    fprintf(stderr, "  -%s %s\n",
            names[i], names[i + 1] == NULL ? "<empty>" : names[i + 1]);
  }
  exit(EXIT_FAILURE);
}


static void verify_document_root(const char *root) {
  const char *p, *path;
  char buf[PATH_MAX];
  struct stat st;

  path = root;
  if ((p = strchr(root, ',')) != NULL && (size_t) (p - root) < sizeof(buf)) {
    memcpy(buf, root, p - root);
    buf[p - root] = '\0';
    path = buf;
  }

  if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
    die("Invalid root directory: [%s]: %s", root, strerror(errno));
  }
}

static char *sdup(const char *str) {
  char *p;
  if ((p = (char *) malloc(strlen(str) + 1)) != NULL) {
    strcpy(p, str);
  }
  return p;
}

static void set_option(char **options, const char *name, const char *value) {
  int i;

  if (!strcmp(name, "document_root") || !(strcmp(name, "r"))) {
    verify_document_root(value);
  }

  // check p44 API passthrough options
  if (strcmp(name, "jsoncsrf_path")==0) {
    strncpy(jsonCSRFPath, value, MAX_API_OPT_CHARS);
  }
  else if (strcmp(name, "nocsrf_paths")==0) {
    strncpy(noCSRFPaths, value, MAX_LONG_OPT_CHARS);
  }
  else if (strcmp(name, "jsonapi_path")==0) {
    strncpy(jsonApiPath, value, MAX_API_OPT_CHARS);
  }
  else if (strcmp(name, "jsonapi_host")==0) {
    strncpy(jsonApiHost, value, MAX_API_OPT_CHARS);
  }
  else if (strcmp(name, "jsonapi_port")==0) {
    strncpy(jsonApiService, value, MAX_API_OPT_CHARS);
  }
  else   if (strcmp(name, "jsoncmd_path")==0) {
    strncpy(jsonCmdlinePath, value, MAX_API_OPT_CHARS);
  }
  else   if (strcmp(name, "jsonupload_path")==0) {
    strncpy(jsonUploadPath, value, MAX_API_OPT_CHARS);
  }
  else   if (strcmp(name, "jsonapiupload_path")==0) {
    strncpy(jsonApiUploadPath, value, MAX_API_OPT_CHARS);
  }
  else   if (strcmp(name, "uploaddir")==0) {
    strncpy(uploadDir, value, MAX_API_OPT_CHARS);
  }
  else if (strcmp(name, "jsoncmd_tool")==0) {
    strncpy(jsonCmdlineTool, value, MAX_API_OPT_CHARS);
  }
  else if (strcmp(name, "extra_auth")==0) {
    strncpy(extraAuth, value, MAX_LONG_OPT_CHARS);
  }
  else {
    // standard mongoose option
    for (i = 0; i < MAX_OPTIONS - 3; i++) {
      if (options[i] == NULL) {
        options[i] = sdup(name);
        options[i + 1] = sdup(value);
        options[i + 2] = NULL;
        break;
      }
    }
    if (i == MAX_OPTIONS - 3) {
      die("%s", "Too many options specified");
    }
  }
}


static void process_command_line_arguments(char *argv[], char **options) {
  char line[MAX_CONF_FILE_LINE_SIZE], opt[sizeof(line)], val[sizeof(line)], *p;
  FILE *fp = NULL;
  size_t i, cmd_line_opts_start = 1, line_no = 0;

  options[0] = NULL;

  // Should we use a config file ?
  if (argv[1] != NULL && argv[1][0] != '-') {
    snprintf(config_file, sizeof(config_file), "%s", argv[1]);
    cmd_line_opts_start = 2;
  } else if ((p = strrchr(argv[0], DIRSEP)) == NULL) {
    // No command line flags specified. Look where binary lives
    snprintf(config_file, sizeof(config_file), "%s", CONFIG_FILE);
  } else {
    snprintf(config_file, sizeof(config_file), "%.*s%c%s",
             (int) (p - argv[0]), argv[0], DIRSEP, CONFIG_FILE);
  }

  fp = fopen(config_file, "r");

  // If config file was set in command line and open failed, die
  if (cmd_line_opts_start == 2 && fp == NULL) {
    die("Cannot open config file %s: %s", config_file, strerror(errno));
  }

  // Load config file settings first
  if (fp != NULL) {
    fprintf(stderr, "Loading config file %s\n", config_file);

    // Loop over the lines in config file
    while (fgets(line, sizeof(line), fp) != NULL) {
      line_no++;

      // Ignore empty lines and comments
      for (i = 0; isspace(* (unsigned char *) &line[i]); ) i++;
      if (line[i] == '#' || line[i] == '\0') {
        continue;
      }

      if (sscanf(line, "%s %[^\r\n#]", opt, val) != 2) {
        printf("%s: line %d is invalid, ignoring it:\n %s",
               config_file, (int) line_no, line);
      } else {
        set_option(options, opt, val);
      }
    }

    (void) fclose(fp);
  }

  // If we're under MacOS and started by launchd, then the second
  // argument is process serial number, -psn_.....
  // In this case, don't process arguments at all.
  if (argv[1] == NULL || memcmp(argv[1], "-psn_", 5) != 0) {
    // Handle command line flags.
    // They override config file and default settings.
    for (i = cmd_line_opts_start; argv[i] != NULL; i += 2) {
      if (argv[i][0] != '-' || argv[i + 1] == NULL) {
        show_usage_and_exit();
      }
      set_option(options, &argv[i][1], argv[i + 1]);
    }
  }
}

static void init_server_name(void) {
  snprintf(
    server_name, sizeof(server_name), "mg44 v%s based on civetweb v%s",
    #if defined(P44_APPLICATION_VERSION)
    P44_APPLICATION_VERSION, // explicit application version override
    #elif defined(PACKAGE_VERSION)
    PACKAGE_VERSION, // automake package version number
    #else
    "????", // none known
    #endif
    mg_version()
  );
}

static int log_message(const struct mg_connection *conn, const char *message) {
  (void) conn;
  printf("%s\n", message);
  return 0;
}



int connectSocket(const char *aHost, const char *aServiceOrPort)
{
  // try to resolve host name
  int res;
  int socketFD = -1;
  struct addrinfo hint;
  struct addrinfo *addressInfoList;
  struct addrinfo *ai = NULL;
  memset(&hint, 0, sizeof(hint));
  hint.ai_flags = 0; // no flags
  hint.ai_family = AF_UNSPEC; // allow all families, aHost decides
  hint.ai_socktype = SOCK_STREAM;
  hint.ai_protocol = 0;
  res = getaddrinfo(aHost, aServiceOrPort, &hint, &addressInfoList);
  if (res==0) {
    // now try all addresses in the list
    ai = addressInfoList;
    while (ai) {
      socketFD = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
      if (socketFD!=-1) {
        // usable address found, socket created
        // - initiate connection
        res = connect(socketFD, ai->ai_addr, ai->ai_addrlen);
        if (res==0) {
          // connection open
          break;
        }
        else {
          // error
          DEBUG_TRACE("Socket connect() failed despite valid address: %s", strerror(errno));
          close(socketFD);
          socketFD = -1;
        }
      }
      // advance to next address
      ai = ai->ai_next;
    }
    // forget the address info
    freeaddrinfo(addressInfoList);
  }
  return socketFD;
}


static size_t json_api_call(char **messageBufP, size_t maxAnswerBytes)
{
  size_t answerSize = 0;
  size_t res,n;
  int done;
  int isJson = 1; // assume JSON
  char *p;
  DEBUG_TRACE("- entered json_api_call");
  int fd = connectSocket(jsonApiHost, jsonApiService);
  DEBUG_TRACE("- connectSocket returns fd=%d", fd);
  if (fd>=0) {
    // write
    write(fd, *messageBufP, strlen(*messageBufP));
    // read
    done = 0;
    while(!done) {
      if (answerSize>=maxAnswerBytes) {
        // enlarge buffer
        if (maxAnswerBytes<0x10000) maxAnswerBytes*=2; else maxAnswerBytes+=0x8000; // double until 64k, then add 32k at a time
        *messageBufP = realloc(*messageBufP, maxAnswerBytes);
      }
      p = *messageBufP+answerSize;
      res = read(fd, p, maxAnswerBytes-answerSize);
      DEBUG_TRACE("- read: res=%zu, maxAnswerBytes=%zu, answerSize=%zu", res, maxAnswerBytes, answerSize);
      if (answerSize==0 && res>0 && (uint8_t)p[0]>=0x80)
        isJson=0; // first byte not ASCII -> can't be JSON
      if (res>0) {
        // got data
        if (isJson) {
          n = 0;
          // - check for LF in byte stream: end of JSON answer
          while (n<res) {
            ++n;
            if (*p=='\n' || *p=='\r') {
              done = 1;
              break;
            }
            ++p;
          }
        }
        else
          n=res; // just take entire data
        answerSize+=n;
      }
      else {
        // done
        break;
      }
    }
    close(fd);
  }
  else {
    DEBUG_TRACE("Error: could not open JSON API socket: %s", strerror(errno));
  }
  return answerSize;
}


extern char **environ;

static size_t json_cmdline_call(char **messageBufP, size_t maxAnswerBytes)
{
  size_t answerSize = 0;
  int pid;
  int answerPipe[2]; /* Child to parent pipe */

  // create a pipe
  if(pipe(answerPipe)>=0) {
    // fork the child
    pid = fork();
    switch(pid) {
      case -1:
        // error forking
        break;
      case 0:
        // Child
        dup2(answerPipe[1], STDOUT_FILENO); // replace STDOUT by writing end of pipe
        close(answerPipe[1]); // release the original descriptor (does NOT really close the file)
        close(answerPipe[0]); // close child's reading end of pipe (parent uses it!)
        // make sure child can detect when it's own children terminate
        // (an ignored SIGCHLD state is inherited from parent - in this
        // case, the mongoose server, which DOES ignore SIGCHLD)
        signal(SIGCHLD, SIG_DFL);
        // close all non-std file descriptors
        int fd = getdtablesize();
        while (fd>STDERR_FILENO) close(fd--);
        // exec the command line tool
        char * args[4];
        args[0] = jsonCmdlineTool;
        args[1] = "--json";
        args[2] = *messageBufP;
        args[3] = NULL;
        execve(jsonCmdlineTool, args, environ); // replace process with new binary/script
        // should not exit, if it does, we have a problem
        exit(EXIT_FAILURE);
      default:
        // Parent
        close(answerPipe[1]); // close parent's writing end (child uses it!)
        ssize_t ret;
        while ((ret = read(answerPipe[0], *messageBufP+answerSize, maxAnswerBytes-answerSize))>0) {
          answerSize += ret;
          if (answerSize>=maxAnswerBytes) {
            // buffer full, assume we'll get more, expand
            maxAnswerBytes += maxAnswerBytes/2; // increase by half of current size
            *messageBufP = realloc(*messageBufP, maxAnswerBytes);
          }
        }
        close(answerPipe[0]);
        int status;
        waitpid(pid, &status, 0);
    }
  }
  return answerSize;
}


static void get_csrf_token(struct mg_connection *conn, char *tok)
{
  const char *remote = mg_get_request_info(conn)->remote_addr;
  //const char *user = mg_get_request_info(conn)->remote_user ? mg_get_request_info(conn)->remote_user : "anonymous";
  const char *user = "irrelevant"; // when we have APIs accessed with and without auth headers, user might be different, so don't include it
  mg_md5(
    tok, // will get MD5 token
    user, // user
    remote, // remote party
    csrf_token_seed, // random ID unique to this mg44 instance
    NULL // terminator
  );
  DEBUG_TRACE("get_csrf_token for conn=%p, user=%s: %s", conn, user, tok);
}


static void request_csrf_token(struct mg_connection *conn)
{
  // create and return csrf protection token
  // - must be unique to the authenticated user
  // - must be unique to this client's IP
  // - must be randomly unique to this running mg44 process, so knowing this hashing function does not help
  char tok[33];
  get_csrf_token(conn, tok);
  mg_printf(
    conn, "HTTP/1.0 200 OK\r\n"
    "%s"
    "Connection: %s\r\n"
    "Content-Length: %zu\r\n"
    "Content-Type: text/plain\r\n\r\n\"%s\"",
    nocache_headers, // do NOT cache CSRF token responses
    suggest_connection_header(conn), // keep-alive or not
    strlen(tok)+2,
    tok
  );
}



static void upload_occurred(struct mg_connection *conn, const char *file_name)
{
  DEBUG_TRACE("uploaded occured, file = %s", lastUploadedFilePath);
  strncpy(lastUploadedFilePath, file_name, MAX_UPLOAD_PATH_LENGTH-1);
}


#if USE_LIBMONGOOSE

static int begin_request(struct mg_connection *conn)
{
  request_handler(conn, NULL);
}

#else

static int authorization_handler(struct mg_connection *conn, void *cbdata)
{
  const char* path = mg_get_request_info(conn)->local_uri;
  // check extra auth first
  // path:path*:path[=[domain@]authfile][,path[=[domain@]authfile]]
  // - : separated paths will all be checked
  // - paths can have * suffix to also match paths beginning with specified string
  // - specifying no auth file allows accessing the path(s) w/o any auth
  // - specifying no domain/realm uses the global auth domain/realm
  const char* p = extraAuth;
  DEBUG_TRACE("path='%s', extraAuth='%s'", path, extraAuth);
  const char* af = NULL;
  const char* de = NULL;
  const char* pe = NULL;
  const char* se = NULL;
  char afn[MAX_API_OPT_CHARS];
  char dmn[MAX_API_OPT_CHARS];
  int authres;
  int wildcard;
  while (*p) {
    wildcard = 0;
    // limit spec
    se = strchr(p, ',');
    if (!se) se = p+strlen(p);
    DEBUG_TRACE("extra_auth spec[%zd]='%.*s'", se-p, (int)(se-p), p);
    // limit path
    pe = strchr(p, ':');
    if (!pe || pe>se) pe = strchr(p, '=');
    if (!pe || pe>se) pe = se;
    if (pe>p && *(pe-1)=='*') {
      wildcard = 1;
    }
    if (strncmp(path, p, wildcard ? pe-p-1 : strlen(path))==0) {
      DEBUG_TRACE("- spec path matches");
      // match, search path
      af = strchr(pe, '=');
      if (af && af<se) {
        // optional domain and auth file path follows
        af++;
        de = strchr(af, '@');
        if (de && de<se) {
          // domain specified
          mg_strnncpy(dmn, af, MAX_API_OPT_CHARS, de-af);
          af = de+1; // skip @
          de = dmn; // domain name
        }
        else {
          de = NULL; // default domain
        }
        mg_strnncpy(afn, af, MAX_API_OPT_CHARS, se-af);
        // check via given authfile path (and nothing else)
        authres = mg_check_access_authentication(conn, de, afn);
        DEBUG_TRACE("authres=%d", authres);
        if (authres>0) {
          DEBUG_TRACE("- AUTHORIZED via auth file");
          return 1; // authorized
        }
        else if (authres==0) {
          // not authorized, but authorizable (auth file exists, params ok) -> request authorization
          DEBUG_TRACE("- authorizable, send auth request");
          if (mg_send_digest_access_authentication_request(conn, de)!=0) {
            DEBUG_TRACE("- ERROR sending auth request");
          }
        }
        DEBUG_TRACE("- not (yet?) authorized");
        return 0; // not authorized, end request here
      }
      else {
        // no '=authfile' means NO authentication required here
        DEBUG_TRACE("- accessible w/o auth");
        return 1; // authorized
      }
      break;
    }
    // no path match
    if (*pe==':') {
      // more paths in this spec to possibly match
      p = pe+1;
    }
    else if (*se==',') {
      // more specs
      p = se+1;
    }
    else {
      break;
    }
  }
  // fall back to standard civetweb check (.htpasswd, global passwd file)
  DEBUG_TRACE("not in any extra_auth scope, checking global auth");
  if (!mg_check_path_authorization(conn, path)) {
    mg_send_digest_access_authentication_request(conn, NULL);
    DEBUG_TRACE("- not (yet?) authorized");
    return 0; // not authorized, end request here
  }
  DEBUG_TRACE("- authorized via global auth");
  return 1; // authorized
}

#endif



static int request_handler(struct mg_connection *conn, void *cbdata)
{
  #define MESSAGE_DEF_SIZE 4096
  char refTok[33];
  char c, *message;
  char *p, *valbuf;
  const char *q, *qvar;
  int firstvar, numeric, numcnt, seendot;
  size_t i, name_length, value_length;
  size_t message_length = 0;
  int withUpload = 0;
  int cmdlineCall = 0;
  int apiCall = 0;
  int csrfValPending = 0;
  // check for csrf protection token call
  size_t prefix_length = strnlen(jsonCSRFPath, MAX_API_OPT_CHARS);
  if (prefix_length>0 && strncmp(mg_get_request_info(conn)->local_uri, jsonCSRFPath, prefix_length)==0) {
    // create and return csrf protection token
    request_csrf_token(conn);
    return 1; // request done
  }
  // check for API calls
  prefix_length = strnlen(jsonApiPath, MAX_API_OPT_CHARS);
  if (prefix_length>0 && strncmp(mg_get_request_info(conn)->local_uri, jsonApiPath, prefix_length)==0) {
    apiCall = 1; // is an API call
  }
  else {
    prefix_length = strnlen(jsonCmdlinePath, MAX_API_OPT_CHARS);
    if (prefix_length>0 && strncmp(mg_get_request_info(conn)->local_uri, jsonCmdlinePath, prefix_length)==0) {
      cmdlineCall = 1; // is a command line call
    }
    else {
      prefix_length = strnlen(jsonUploadPath, MAX_API_OPT_CHARS);
      if (prefix_length>0 && strncmp(mg_get_request_info(conn)->local_uri, jsonUploadPath, prefix_length)==0) {
        cmdlineCall = 1; // is a command line call...
        withUpload = 1; // ...with upload
      }
      else {
        prefix_length = strnlen(jsonApiUploadPath, MAX_API_OPT_CHARS);
        if (prefix_length>0 && strncmp(mg_get_request_info(conn)->local_uri, jsonApiUploadPath, prefix_length)==0) {
          apiCall = 1; // is a JSON call...
          withUpload = 1; // ...with upload
        }
      }
    }
  }
  if (apiCall || cmdlineCall) {
    // JSON API call to deliver to a daemon or the commandline
    size_t msgBufSz = MESSAGE_DEF_SIZE;
    message = malloc(msgBufSz);
    // create pure JSON request
    // { "method" : "GET", "uri" : "/myuri" }
    // { "method" : "POST", "uri" : "/myuri", ["uri_params":{}] "data" : <{ JSON payload }>}
    message_length = snprintf(
      message, msgBufSz,
      "{ \"method\":\"%s\", \"uri\":\"%s\", \"peer\":\"%s\"",
      mg_get_request_info(conn)->request_method,
      mg_get_request_info(conn)->local_uri+prefix_length, // rest of URI
      mg_get_request_info(conn)->remote_addr // peer's IP address
    );
    if (*jsonCSRFPath!=0) {
      // CSRF checking is on
      csrfValPending = 1;
      // check for paths excluded from CSRF checking
      // path[:path ...]
      const char* p = noCSRFPaths;
      while (*p) {
        const char* pe = strchr(p, ':');
        if (strncmp(p, mg_get_request_info(conn)->local_uri, pe ? pe-p : strlen(p))==0) {
          // matches one of the paths that must not have CSRF checking
          csrfValPending = 0;
          break;
        }
        if (!pe) break;
        p = pe+1;
      }
    }
    // check query variables
    q = mg_get_request_info(conn)->query_string;
    if (q && *q) {
      message_length += snprintf(message+message_length, msgBufSz-message_length,", \"uri_params\": {");
      firstvar = 1;
      // parse variables
      while (q && *q) {
        // find name end
        qvar = q; // name start
        while (*q && *q!='=' && *q!='&') q++; // name end
        // add name and begin of string
        if (!firstvar)
          message_length += snprintf(message+message_length, msgBufSz-message_length,", ");
        name_length = (int)(q-qvar);
        message_length += snprintf(message+message_length, msgBufSz-message_length,"\"%.*s\": ", (int)name_length, qvar);
        firstvar = 0;
        // check value
        if (*q=='=') {
          // has value
          // check for csrf token
          if (csrfValPending && strncmp("rqvaltok", qvar, name_length)==0) {
            // is token, check it
            get_csrf_token(conn, refTok);
            if (strncmp(refTok, q+1, strlen(refTok))==0) {
              // matching token found
              csrfValPending = 0; // allowed to run the request
            }
          }
          qvar = ++q; // beginning of value
          numeric = 1; // assume pure numeric
          numcnt = 0;
          seendot = 0;
          while (*q && *q!='&') {
            if (!(isdigit(*q) || (*q=='.' && !seendot) || (*q=='-' && numcnt==0)))
              numeric = 0; // not pure numeric value
            if (*q=='.') seendot=1;
            numcnt++;
            q++; // search end of value
          }
          // process value
          value_length = q-qvar;
          if (numeric) {
            // just copy
            i = mg_url_decode(qvar, (int)value_length, message+message_length, (int)(msgBufSz-message_length), 0);
            if (i>0) message_length += i;
          }
          else {
            // string, quote and escape
            message_length += snprintf(message+message_length, msgBufSz-message_length,"\""); // string lead-in
            // decode into intermediate buffer
            valbuf = malloc(value_length*2); // worst case is that every char needs to be escaped
            if (valbuf) {
              i = mg_url_decode(qvar, (int)value_length, valbuf, (int)value_length*2, 0);
              if (i>0) {
                // now process decoded string and escape for JSON if needed
                for (p=valbuf; i>0; --i, ++p) {
                  if (message_length>=msgBufSz-2) break; // no room for at least 2 chars any more
                  c = *p;
                  if (*p=='\\' || *p=='"' || *p<0x20) {
                    // need escaping
                    message[message_length++] = '\\';
                    // catch those that can't be escaped as-is
                    switch (*p) {
                      case 0x08 : c = 'b'; break; // backspace
                      case 0x09 : c = 't'; break; // tab
                      case 0x0A : c = 'n'; break; // linefeed
                      case 0x0C : c = 'f'; break; // formfeed
                      case 0x0D : c = 'r'; break; // carriage return
                    }
                  }
                  message[message_length++] = c;
                }
              }
              free(valbuf);
            }
            message_length += snprintf(message+message_length, msgBufSz-message_length,"\""); // string lead-out
          }
        }
        else {
          // no value
          message_length += snprintf(message+message_length, msgBufSz-message_length,"null");
        }
        if (*q) q++; // skip var separator
      }
      // end of query params
      message_length += snprintf(message+message_length, msgBufSz-message_length," }");
    }
    // add data if PUT or POST
    if (
      strcmp(mg_get_request_info(conn)->request_method, "POST")==0 ||
      strcmp(mg_get_request_info(conn)->request_method, "PUT")==0
    ) {
      if (withUpload && *uploadDir!=0) {
        // PUT or POST carries file upload(s)
        lastUploadedFilePath[0]=0;
        int numfiles = mg_upload(conn, uploadDir);
        if (numfiles>=1) {
          // pass last uploaded file name with JSON query
          message_length += snprintf(message+message_length, msgBufSz-message_length, ", \"uploadedfile\": \"%s\"", lastUploadedFilePath);
          DEBUG_TRACE("uploaded %d files, last uploaded = %s", numfiles, lastUploadedFilePath);
        }
        lastUploadedFilePath[0]=0;
      }
      else {
        // put or post carrying JSON data
        message_length += snprintf(message+message_length, msgBufSz-message_length, ", \"data\": ");
        // get POST/PUT payload data
        while (1) {
          size_t remSz = msgBufSz-message_length-1;
          p = message+message_length; // recalculate for every iteration, as buffer might have relocated
          size_t n = mg_read(conn, p, remSz);
          if (n==0) {
            // all read
            break;
          }
          message_length += n;
          remSz -= n;
          // replace all whitespace by actual space chars (eliminating line feeds)
          while (n>0) {
            if (isspace(*p))
              *p = ' ';
            ++p;
            --n;
          }
          // maybe we need more buffer space
          if (remSz==0) {
            // buffer exhausted
            if (msgBufSz<0x10000) msgBufSz*=2; else msgBufSz+=0x8000; // double until 64k, then add 32k at a time
            message = realloc(message, msgBufSz);
          }
        }
      }
    }
    // end of JSON object + LF
    message_length += snprintf(message+message_length, msgBufSz-message_length," }\n");
    DEBUG_TRACE("request json = %s", message);
    // abort call if csrf token is not ok
    if (csrfValPending) {
      // abort
      DEBUG_TRACE("csrf token does not match");
      free(message); message = NULL;
      mg_printf(conn, "HTTP/1.0 403 Forbidden\r\n%s\r\n<html><body><h1>forbidden</h1></body></html>", nocache_headers);
      return 1; // request handled
    }
    else if (apiCall) {
      // send json request, receive answer
      DEBUG_TRACE("calling json_api_call()");
      message_length = json_api_call(&message, msgBufSz);
      DEBUG_TRACE("called json_api_call() = %zu", message_length);
      message[message_length]=0; // terminate
    }
    else if (cmdlineCall) {
      DEBUG_TRACE("calling json_cmdline_call()");
      message_length = json_cmdline_call(&message, msgBufSz);
      DEBUG_TRACE("called json_cmdline_call() = %zu", message_length);
      message[message_length]=0; // terminate
    }
    // start answer
    mg_printf(conn, "HTTP/1.0 200 OK\r\n");
    const char *contentType;
    int contentType_len = 0;
    const char *msgP = message;
    // analyze answer
    // - check for PNG header: 0x89504E47 = 0x89 'P' 'N' 'G'
    if (
      message_length>4 &&
      (uint8_t)message[0]==0x89 &&
      (uint8_t)message[1]==0x50 &&
      (uint8_t)message[2]==0x4E &&
      (uint8_t)message[3]==0x47
    ) {
      // is PNG
      DEBUG_TRACE("detected PNG answer from socket API");
      contentType = "image/png";
      contentType_len = (int)strlen(contentType);
    }
    else {
      // - check for custom content and headers
      i=0;
      while (i<message_length) {
        if (message[i]==0x03) {
          // ctrl-C for "content type"
          contentType = &message[++i];
          while (i<message_length && message[i++]>=0x20) contentType_len++;
          DEBUG_TRACE("detected custom content type (^C): %.*s", contentType_len, contentType);
        }
        else if (message[i]==0x08) {
          // ctrl-H for header line as-is
          i++;
          int n = 0;
          while (i+n<message_length && message[i+n]>=0x20) n++;
          DEBUG_TRACE("detected custom header line (^H): %.*s", n, &message[i]);
          mg_printf(conn, "%.*s\r\n", n, &message[i]);
          i+=n;
        }
        else {
          // done with special prefix lines
          break;
        }
        // skip CRLF
        if (i<message_length && message[i]==0x0D) i++;
        if (i<message_length && message[i]==0x0A) i++;
      }
      // skip prefixes
      msgP = &message[i];
      message_length -= i;
    }
    if (contentType_len==0) {
      // assume JSON
      DEBUG_TRACE("assuming content type json for response from socket API");
      contentType = "application/json";
      contentType_len = (int)strlen(contentType);
    }
    mg_printf(
      conn,
      "%s" // no cache headers
      "Connection: %s\r\n"
      "Content-Length: %zu\r\n"
      "Content-Type: %.*s\r\n\r\n",
      nocache_headers, // do NOT cache JSON responses
      suggest_connection_header(conn), // keep-alive or not
      message_length, contentType_len, contentType
    );
    DEBUG_TRACE("response body = %.*s", (int)message_length, msgP);
    mg_write(conn, msgP, message_length);
    // done
    free(message); message = NULL;
    // Returning non-zero tells mongoose that our function has replied to
    // the client, and mongoose should not send client any more data.
    return 1;

  }
  // Returning zero tells mongoose that our function has NOT replied to
  // the client, and mongoose should process the request
  return 0;
}


static void start_mongoose(int argc, char *argv[]) {
  struct mg_callbacks callbacks;
  char *options[MAX_OPTIONS];
  int i;

  // init p44 options
  jsonCSRFPath[0] = 0;
  noCSRFPaths[0] = 0;
  jsonApiPath[0] = 0;
  jsonApiHost[0] = 0;
  jsonApiService[0] = 0;
  jsonApiUploadPath[0] = 0;
  jsonCmdlinePath[0] = 0;
  jsonCmdlineTool[0] = 0;
  jsonUploadPath[0] = 0;
  uploadDir[0] = 0;
  extraAuth[0] = 0;

  // Edit passwords file if -A option is specified
  if (argc > 1 && !strcmp(argv[1], "-A")) {
    if (argc != 6) {
      show_usage_and_exit();
    }
    exit(mg_modify_passwords_file(argv[2], argv[3], argv[4], argv[5]) ?
         EXIT_SUCCESS : EXIT_FAILURE);
  }

  // Open Download connection
  //  1 2      3    4   5           6
  // -D method host doc contenttype body
  if (argc >= 5 && !strcmp(argv[1], "-D")) {
    struct mg_connection *mgConn = NULL; // mongoose connection
    const size_t ebufSz = 300;
    char ebuf[ebufSz];
    // is a request which sends data in the HTTP message body (e.g. POST)
    mgConn = mg_download(
      argv[3], // host
      443,
      1,
      ebuf, ebufSz,
      "%s %s HTTP/1.1\r\n"
      "Host: %s\r\n"
      "Content-Type: %s; charset=UTF-8\r\n"
      "Content-Length: %zu\r\n"
      "\r\n"
      "%s",
      argv[2], // method
      argv[4], // doc
      argv[3], // host
      argc>5 ? argv[5] : "text/html", // content type
      argc>6 ? strlen(argv[6]) : 0, // body len
      argc>6 ? argv[6] : "" // body
    );
    if (!mgConn) {
      printf("Civetweb error: %s\n", ebuf);
    }
    else {
      printf("Connection OK\n");
      const size_t bufferSz = 2048;
      uint8_t buffer[bufferSz];
      while (1) {
        ssize_t res = mg_read(mgConn, buffer, bufferSz);
        if (res==0) {
          // connection has closed, all bytes read
          break;
        }
        else if (res<0) {
          // read error
          printf("Read error: %s\n", strerror(errno));
          break;
        }
        else {
          fwrite(buffer, res, 1, stdout);
        }
      }
      mg_close_connection(mgConn);
    }
    exit(0);
  }


  // Show usage if -h or --help options are specified
  if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
    show_usage_and_exit();
  }
  // Show version if -V option is specified
  if (argc == 2 && !strcmp(argv[1], "-V")) {
    show_version();
    exit(EXIT_SUCCESS);
  }

  /* Update config based on command line arguments */
  process_command_line_arguments(argv, options);

  /* Setup signal handler: quit on Ctrl-C */
  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);

  /* Start Civetweb */
  memset(&callbacks, 0, sizeof(callbacks));
  // Install log callback
  callbacks.log_message = &log_message;
  // Install request handler callback to catch API calls
  #if USE_LIBMONGOOSE
  // Install request handler callback to catch API calls
  // Note: Cannot be used any more from civetweb 1.7 onwards because it does not any longer check http auth
  callbacks.begin_request = &begin_request;
  #endif
  // Install handler to catch uploads
  callbacks.upload = &upload_occurred;
  // start
  ctx = mg_start(&callbacks, NULL, (const char **) options);
  for (i = 0; options[i] != NULL; i++) {
    free(options[i]);
  }
  if (ctx == NULL) {
    die("%s", "Failed to start Civetweb.");
  }
  #if !USE_LIBMONGOOSE
  // register handlers
  mg_set_request_handler(ctx, "/", request_handler, NULL);
  mg_set_auth_handler(ctx, "/", authorization_handler, NULL);
  #endif
}


int main(int argc, char *argv[]) {
  srand((int)argv[0]); // memory pointer as seed
  sprintf(csrf_token_seed, "%08lX", (long)rand());
  init_server_name();
  start_mongoose(argc, argv);
  printf("%s started on port(s) %s with web root [%s]\n",
         server_name, mg_get_option(ctx, "listening_ports"),
         mg_get_option(ctx, "document_root"));
  while (exit_flag == 0) {
    sleep(1);
  }
  printf("Exiting on signal %d, waiting for all threads to finish...",
         exit_flag);
  fflush(stdout);
  mg_stop(ctx);
  printf("%s", " done.\n");

  return EXIT_SUCCESS;
}
