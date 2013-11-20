// Copyright (c) 2004-2013 Sergey Lyubka
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

#include "mongoose.h"

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



#define DIRSEP '/'

#define MAX_OPTIONS 40
#define MAX_CONF_FILE_LINE_SIZE (8 * 1024)

static int exit_flag;
static char server_name[40];        // Set by init_server_name()
static char config_file[PATH_MAX];  // Set by process_command_line_arguments()
static struct mg_context *ctx;      // Set by start_mongoose()

#ifdef __APPLE__
#define MAX_API_OPT_CHARS 400
#else
#define MAX_API_OPT_CHARS 40
#endif
// JSON REST API passtrough
static char jsonApiPath[MAX_API_OPT_CHARS]; // path prefix for JSON API passthrough
static char jsonApiHost[MAX_API_OPT_CHARS]; // host name/IP for JSON API passthrough
static char jsonApiService[MAX_API_OPT_CHARS]; // service name or port number for JSON API pass through
// JSON command line API passtrough
static char jsonCmdlinePath[MAX_API_OPT_CHARS]; // path prefix for JSON command line passthrough
static char jsonCmdlineTool[MAX_API_OPT_CHARS]; // full path for command line tool which handles JSON requests


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

static void show_usage_and_exit(void) {
  const char **names;
  int i;

  fprintf(stderr, "Mongoose version %s (c) Sergey Lyubka, built on %s\n",
          mg_version(), __DATE__);
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  mongoose -A <htpasswd_file> <realm> <user> <passwd>\n");
  fprintf(stderr, "  mongoose [config_file]\n");
  fprintf(stderr, "  mongoose [-option value ...]\n");
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
  if (strcmp(name, "jsonapi_path")==0) {
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
  else if (strcmp(name, "jsoncmd_tool")==0) {
    strncpy(jsonCmdlineTool, value, MAX_API_OPT_CHARS);
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
  snprintf(server_name, sizeof(server_name), "Mongoose web server v. %s",
           mg_version());
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
  hint.ai_family = AF_INET;
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
      }
      // advance to next address
      ai = ai->ai_next;
    }
    // forget the address info
    freeaddrinfo(addressInfoList);
  }
  return socketFD;
}



static size_t json_api_call(char *messageBuf, size_t maxAnswerBytes)
{
  size_t answerSize = 0;
  size_t res,n;
  int done;
  char *p;
  int fd = connectSocket(jsonApiHost, jsonApiService);
  if (fd>=0) {
    // write
    write(fd, messageBuf, strlen(messageBuf));
    // read
    p = messageBuf+answerSize;
    done = 0;
    while(answerSize<maxAnswerBytes && !done) {
      res = read(fd, p, maxAnswerBytes-answerSize);
      if (res>0) {
        // got data
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
        answerSize+=n;
      }
      else {
        // done
        break;
      }
    }
    close(fd);
  }
  return answerSize;
}


extern char **environ;

static size_t json_cmdline_call(char *messageBuf, size_t maxAnswerBytes)
{
  size_t answerSize = 0;
	int pid;
	int answerPipe[2]; /* Child to parent pipe */

	// create a pipe
  fprintf(stderr,"creating pipe...\n"); fflush(stderr);
	if(pipe(answerPipe)>=0) {
    // fork the child
	  fprintf(stderr,"pipe ok, forking process...\n"); fflush(stderr);
    pid = fork();
    switch(pid) {
      case -1:
        // error forking
        fprintf(stderr,"ERROR forking process %d\n", errno); fflush(stderr);
        break;
      case 0:
        // Child
        fprintf(stderr,"Child forked\n"); fflush(stderr);
        dup2(answerPipe[1], STDOUT_FILENO); // replace STDOUT by writing end of pipe
        close(answerPipe[1]); // release the original descriptor (does NOT really close the file)
        close(answerPipe[0]); // close child's reading end of pipe (parent uses it!)
        // close all non-std file descriptors
        int fd = getdtablesize();
        fprintf(stderr,"Highest fd is %d\n", fd); fflush(stderr);
        //while (fd-- > 2) close(fd);
        //fprintf(stderr,"All fds>2 closed\n"); fflush(stderr);
        // exec the command line tool
        char * args[4];
        args[0] = jsonCmdlineTool;
        args[1] = "--json";
        args[2] = messageBuf;
        args[3] = NULL;
        fprintf(stderr,"Calling jommand line tool '%s' now with message = '%s'\n", jsonCmdlineTool, messageBuf); fflush(stderr);
        execve(jsonCmdlineTool, args, environ); // replace process with new binary/script
        // should not exit, if it does, we have a problem
        exit(EXIT_FAILURE);
      default:
        // Parent
        close(answerPipe[1]); // close parent's writing end (child uses it!)
        // make paren'ts reading end non-blocking so we can wait for child termination AND data on the pipe
        fprintf(stderr,"parent: making answer pipe non-blocking to read from\n"); fflush(stderr);
        int flags;
        if ((flags = fcntl(answerPipe[0], F_GETFL, 0))==-1)
          flags = 0;
        fcntl(answerPipe[0], F_SETFL, flags | O_NONBLOCK);
        fprintf(stderr,"parent: starting to wait for process to die AND read from pipe\n"); fflush(stderr);
        ssize_t ret;
        int status;
        pid_t pid2;
        ret = 0; // no error on pipe yet
        pid2 = 0; // not terminated yet
        while (1) {
          // try to read data
          if (ret>=0) {
            // still open
            ret = read(answerPipe[0], messageBuf+answerSize, maxAnswerBytes-answerSize);
            if (ret!=0) {
              if (errno==EWOULDBLOCK) {
                // no data, just go on
                ret = 0; // reset error condition
              }
              else {
                // other error
                fprintf(stderr,"read(answerPipe[0]) returns %ld, err=%d (%s)\n", ret, errno, strerror(errno)); fflush(stderr);
              }
            }
            if (ret>0) {
              answerSize += ret;
            }
            if (ret==0) {
              // no more data
              ret = -1; // simulate error condition
            }
          }
          // check for process termination
          if (pid<=0) {
            // still waiting for termination
            pid2 = waitpid(pid, &status, WNOHANG);
            if (pid2>0) {
              fprintf(stderr,"child has terminated\n"); fflush(stderr);
            }
          }
          if (pid2>0 && ret<0) {
            // terminated and all pipe data read
            break;
          }
          // wait a little
          sleep(1);
        }
        close(answerPipe[0]);
        fprintf(stderr,"pipe has ended and child has exited with status=%d\n", status); fflush(stderr);
        break;
    }
  }
  return answerSize;
}




static int begin_request(struct mg_connection *conn)
{
  #define MESSAGE_MAX_SIZE 4096
  char *message;
  char *p;
  const char *q, *qvar;
  int firstvar, numeric;
  size_t i;
  size_t message_length = 0;
  int cmdlineCall = 0;
  int apiCall = 0;
  // check for API
  size_t n = strnlen(jsonApiPath, MAX_API_OPT_CHARS);
  if (n>0 && strncmp(mg_get_request_info(conn)->uri, jsonApiPath, n)==0) {
    apiCall = 1; // is an API call
  }
  else {
    size_t n = strnlen(jsonCmdlinePath, MAX_API_OPT_CHARS);
    if (n>0 && strncmp(mg_get_request_info(conn)->uri, jsonCmdlinePath, n)==0) {
      cmdlineCall = 1; // is an API call
    }
  }
  if (apiCall || cmdlineCall) {
    // JSON call to deliver to a daemon or the commandline
    message = malloc(MESSAGE_MAX_SIZE);
    // create pure JSON request
    // { "method" : "GET", "uri" : "/myuri" }
    // { "method" : "POST", "uri" : "/myuri", ["uri_params":{}] "data" : <{ JSON payload }>}
    message_length = snprintf(
      message, MESSAGE_MAX_SIZE,
      "{ \"method\":\"%s\", \"uri\":\"%s\"",
      mg_get_request_info(conn)->request_method,
      mg_get_request_info(conn)->uri+n // rest of URI
    );
    // check query variables
    q = mg_get_request_info(conn)->query_string;
    if (q && *q) {
      message_length += snprintf(message+message_length, MESSAGE_MAX_SIZE-message_length,", \"uri_params\": {");
      firstvar = 1;
      // parse variables
      while (q && *q) {
        // find name end
        qvar = q; // name start
        while (*q && *q!='=' && *q!='&') q++; // name end
        // add name and begin of string
        if (!firstvar)
          message_length += snprintf(message+message_length, MESSAGE_MAX_SIZE-message_length,", ");
        message_length += snprintf(message+message_length, MESSAGE_MAX_SIZE-message_length,"\"%.*s\": ", (int)(q-qvar), qvar);
        firstvar = 0;
        // check value
        if (*q=='=') {
          // has value
          qvar = ++q; // beginning of value
          numeric = 1; // assume pure numeric
          while (*q && *q!='&') {
            if (!isdigit(*q) && *q!='.' && *q!='-')
              numeric = 0; // not pure numeric value
            q++; // search end of value
          }
          if (!numeric) message_length += snprintf(message+message_length, MESSAGE_MAX_SIZE-message_length,"\""); // string lead-in
          i = mg_url_decode(qvar, (int)(q-qvar), message+message_length, (int)(MESSAGE_MAX_SIZE-message_length), 0);
          if (i>0) message_length += i;
          if (!numeric) message_length += snprintf(message+message_length, MESSAGE_MAX_SIZE-message_length,"\""); // string lead-out
        }
        else {
          // no value
          message_length += snprintf(message+message_length, MESSAGE_MAX_SIZE-message_length,"null");
        }
        if (*q) q++; // skip var separator
      }
      // end of query params
      message_length += snprintf(message+message_length, MESSAGE_MAX_SIZE-message_length," }");
    }
    // add data if PUT or POST
    if (
      strcmp(mg_get_request_info(conn)->request_method, "POST")==0 ||
      strcmp(mg_get_request_info(conn)->request_method, "PUT")==0
    ) {
      // put or post
      message_length += snprintf(message+message_length, MESSAGE_MAX_SIZE-message_length,", \"data\": ");
      // get POST/PUT payload data
      p = message+message_length;
      size_t n = mg_read(conn, p, MESSAGE_MAX_SIZE-message_length-1);
      size_t payloadLen = n;
      // replace all whitespace by actual space chars (eliminating line feeds)
      while (n>0) {
        if (isspace(*p))
          *p = ' ';
        ++p;
        --n;
      }
      message_length += payloadLen;
    }
    // end of JSON object + LF
    message_length += snprintf(message+message_length, MESSAGE_MAX_SIZE-message_length," }\n");
    if (apiCall) {
      // send json request, receive answer
      message_length = json_api_call(message, MESSAGE_MAX_SIZE);
      message[message_length]=0; // terminate
    }
    else if (cmdlineCall) {
      message_length = json_cmdline_call(message, MESSAGE_MAX_SIZE);
      message[message_length]=0; // terminate
    }
    // return JSON answer
    // Show HTML form.
    mg_printf(
      conn, "HTTP/1.0 200 OK\r\n"
      "Content-Length: %ld\r\n"
      "Content-Type: text/html\r\n\r\n%s",
      message_length, message
    );
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

  // p44 API passthrough option init
  jsonApiHost[0] = 0;
  jsonApiPath[0] = 0;
  jsonApiService[0] = 0;

  // Edit passwords file if -A option is specified
  if (argc > 1 && !strcmp(argv[1], "-A")) {
    if (argc != 6) {
      show_usage_and_exit();
    }
    exit(mg_modify_passwords_file(argv[2], argv[3], argv[4], argv[5]) ?
         EXIT_SUCCESS : EXIT_FAILURE);
  }

  // Show usage if -h or --help options are specified
  if (argc == 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
    show_usage_and_exit();
  }

  /* Update config based on command line arguments */
  process_command_line_arguments(argv, options);

  /* Setup signal handler: quit on Ctrl-C */
  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);

  /* Start Mongoose */
  memset(&callbacks, 0, sizeof(callbacks));
  // Install log callback
  callbacks.log_message = &log_message;
  // Install request handler callback to catch API calls
  callbacks.begin_request = &begin_request;

  ctx = mg_start(&callbacks, NULL, (const char **) options);
  for (i = 0; options[i] != NULL; i++) {
    free(options[i]);
  }

  if (ctx == NULL) {
    die("%s", "Failed to start Mongoose.");
  }
}


int main(int argc, char *argv[]) {
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
