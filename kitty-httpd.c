/* 
kitty-httpd.c 
A lightweight web server

v. 0.0.5
Copyright (C) 2008-2009 Kitt Tientanopajai

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as 
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

ChangeLogs
----------

  - Fix problem with broken symlinks.
  - Header should use CRLF for end-of-line.
  - Make use of thread-safe functions
    - localtime_r(), strtok_r()
  - syslog is now optional
    - Use -l to enable
* Fri, 11 Sep 2009 21:16:45 +0700 - v0.0.5
  - Add manpage and more help messages
  - Use GPL-compatible code to unescape
    - Use W3C instead of MPL.
  - Add option -u for setting effective user
  - Move all console messages to syslog facility 
    - kitty-httpd uses LOG_LOCAL0
  - Add IPv6 support
  - Add option -i for directory index
  - Add option -v for version
  - Cleanup indent & re-tab
  - Bugs fixed
    - The recv loop does not read properly
    - Free client_sockfd (too many open files)
    - Client termination may cause broken pipe (SIGPIPE)
      - Ref: Neutron Soutmun
    - Properly close client socket if a thread cannot be created.
    - GET / does not log URL properly when use_directory_index = 1

* Fri, 24 Jul 2009 20:23:18 +0700 -v0.0.4
  - Add SO_REUSEADDR 
  - Rewrite sendfile loop
  - Capable to transfer file size >= 2 GB
  - GNU Coding Style
  - Honour index.html if exists
  - Capable to handle escaped URLs
  - Add HTML code for errors
  - Bugs fixed
    - Properly stop the server when receiving SIGINT (Ctrl+C)
    - Long-waiting 'cancel download' handle
    - Threads do not exit properly causing high memory consumption
    - Memory leaks in threads
    - File size should be long long unsigned
    - Content length should be long long unsigned

* Mon, 06 Oct 2008 01:00:46 +0700 - v0.0.3
  - Use current directory as default base directory
  - Add option -p port
  - Add option -d base directory
  - Implement directory index
  - Add more MIME type (i.e., OpenOffice)
  - Bugs fixed 
    - Send HTTP version according to the request
    - Correct some MIME Types

* Tue, 30 Sep 2008 20:04:02 +0700 - v0.0.2
  - Implement all HTTP/1.1 requirement (GET, HEAD)
  - Response based on version requested
  - NPTL-based Multithreading
  - MIME supported based on file extension
  - Bugs fixed

* Sat, 27 Sep 2008 23:06:18 +0700 - v0.0.1
  - Initial version
  - Implement GET method only
  - HTTP/0.9

Known Issues
------------
  - Large number of requests may cause segfault if index.html does not exist

To Do
-----
  - Secure programming
  - Network optimization
  - Beautify the index page + CSS

Not-so-near-future To Do
------------------------
  - GNOME Notification Area

*/

#define _FILE_OFFSET_BITS 64
#define __USE_LARGEFILE64 1
#define __USE_FILE_OFFSET64 1

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <pthread.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <getopt.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <syslog.h>
#include <pwd.h>

#define BACKLOG 16
#define BUFFER_SIZE 1024
#define CHUNK_SIZE 1073741824
#define HEADER_MAX 256
#define URL_MAX 256
#define VERSION "0.0.5"
#define SERVER_VERSION "Kitty-HTTPD/0.0.5"

static void *sig_int (int);
static void *service_client (void *);
static char *get_index_page (char *);
static char *get_mime_type (char *);
static void unescape (char *);
static inline unsigned char hex (char);
static void help (char *);

char basedir[PATH_MAX];
int stop = 0;
int use_dir_index = 0;
int use_syslog = 0;

int
main (int argc, char *argv[])
{
  int server_sockfd;
  struct sockaddr_in6 server_addr;
  unsigned short server_port = 8080;
  int use_ipv6_only = 0;
  int use_so_reuseaddr = 0;
  int use_euid = 0;
  int opt;
  char username[32];

  strncpy (basedir, ".", 1);
  memset (username, '\0', sizeof username);

  /* parse argument */
  static const struct option longopts[] = 
    {
      {"v6only",    0, NULL, '6'},
      {"docroot",   1, NULL, 'd'},
      {"path",      1, NULL, 'd'},
      {"help",      0, NULL, 'h'},
      {"index",     0, NULL, 'i'},
      {"log",       0, NULL, 'l'},
      {"port",      1, NULL, 'p'},
      {"reuseaddr", 0, NULL, 'r'},
      {"user",      1, NULL, 'u'},
      {"version",   0, NULL, 'v'},
      {0, 0, 0, 0}
    };

  while ((opt = getopt_long (argc, argv, "6d:hilp:ru:v", longopts, 0)) != -1)
    {
      switch (opt)
        {
        case '6':
          use_ipv6_only = 1;
          break;
        case 'd':
          strncpy (basedir, optarg, (sizeof basedir) - 1);
          basedir[(sizeof basedir) - 1] = '\0';
          break;
        case 'h':
          help (argv[0]);
          exit (EXIT_SUCCESS);
        case 'i':
          use_dir_index = 1;
          break;
        case 'l':
          use_syslog = 1;
          break;
        case 'p':
          server_port = atoi (optarg) % 65536;
          break;
        case 'r':
          use_so_reuseaddr = 1;
          break;
        case 'u':
          use_euid = 1;
          strncpy (username, optarg, (sizeof username) - 1);
          username[(sizeof username) - 1] = '\0';
          break;
        case 'v':
          printf ("%s %s\n", argv[0], VERSION);
          exit (EXIT_SUCCESS);
        default:
          exit (EXIT_FAILURE);
        }
    }

  /* start log facility */
  if (use_syslog)
    openlog ("kitty-http",
             LOG_CONS | LOG_NDELAY | LOG_NOWAIT | LOG_PERROR | LOG_PID,
             LOG_LOCAL0);

  /* seteuid if needed */
  if (use_euid) 
    {
      struct passwd *pwd = getpwnam (username);
      if (pwd == NULL) 
        {
          endpwent ();
          switch (errno) 
            {
            case (0):
            case (ENOENT):
            case (ESRCH):
            case (EBADF):
            case (EPERM):
              if (use_syslog)
                syslog (LOG_ERR, "error user %s not found", username);
              break;
            default:
              if (use_syslog)
                syslog (LOG_ERR, "error %m");
            }
          exit (EXIT_FAILURE);
        }

      if (seteuid (pwd -> pw_uid) == -1)
        {
          endpwent ();

          if (use_syslog)
            syslog (LOG_ERR, "error seteuid %m");

          exit (EXIT_FAILURE);
        }

      endpwent ();
    }

  /* test basedir */
  char cwd[PATH_MAX];
  if (getcwd (cwd, PATH_MAX) == NULL)
    {
      if (use_syslog)
        syslog (LOG_ERR, "error getcwd %m");

      exit (EXIT_FAILURE);
    }

  if (chdir (basedir) == -1)
    {
      if (use_syslog)
        syslog (LOG_ERR, "error cannot change working directory %m");

      exit (EXIT_FAILURE);
    }

  if (getcwd (basedir, PATH_MAX) == NULL)
    {
      if (use_syslog)
        syslog (LOG_ERR, "error getcwd %m");

      exit (EXIT_FAILURE);
    }

  /* signal handler */
  signal (SIGINT, (void *) sig_int);
  signal (SIGPIPE, SIG_IGN);
  siginterrupt (SIGINT, 1);

  /* create socket */
  if ((server_sockfd = socket (PF_INET6, SOCK_STREAM, 0)) == -1)
    {
      if (use_syslog)
        syslog (LOG_ERR, "error opening socket: %m");

      exit (EXIT_FAILURE);
    }

  server_addr.sin6_family = AF_INET6;
  server_addr.sin6_port = htons (server_port);
  server_addr.sin6_addr = in6addr_any;

  if (setsockopt
      (server_sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &use_ipv6_only,
       sizeof use_ipv6_only) == -1)
    {
      if (use_syslog)
        syslog (LOG_INFO, "cannot setting IPV6_V6ONLY: %m");
    }


  if (setsockopt
      (server_sockfd, SOL_SOCKET, SO_REUSEADDR, &use_so_reuseaddr,
       sizeof use_so_reuseaddr) == -1)
    {
      if (use_syslog)
        syslog (LOG_INFO, "cannot setting SO_REUSEADDR: %m");
    }

  /* bind port */
  if ((bind
       (server_sockfd, (const struct sockaddr *) &server_addr,
        sizeof (struct sockaddr_in6))) == -1)
    {
      if (use_syslog)
        syslog (LOG_ERR, "error binding port: %m");

      exit (EXIT_FAILURE);
    }

  /* listen */
  if (listen (server_sockfd, BACKLOG) == -1)
    {
      if (use_syslog)
        syslog (LOG_ERR, "error listening for connections: %m");

      exit (EXIT_FAILURE);
    }

  struct passwd *pwd = getpwuid (geteuid ());

  if (use_syslog)
    syslog (LOG_INFO,
            "user %s starts kitty-httpd at port %u, document root = %s.",
            pwd -> pw_name, server_port, basedir);
  else
    printf ("user %s starts kitty-httpd at port %u, document root = %s.\n",
            pwd -> pw_name, server_port, basedir);

  /* main loop - accept a connection, thread out service function */
  while (!stop)
    {
      int client_sockfd;
      struct sockaddr_in6 client_addr;
      socklen_t client_addr_len = sizeof client_addr;

      if ((client_sockfd =
           accept (server_sockfd, (struct sockaddr *) &client_addr,
                   &client_addr_len)) != -1)
        {
          pthread_t tid;

          if (pthread_create
              (&tid, NULL, service_client, (void *) client_sockfd))
            {
              if (use_syslog)
                syslog (LOG_INFO, "error creating service thread: %m");

              shutdown ((int) client_sockfd, SHUT_RDWR);
              close ((int) client_sockfd);
            }
          else
            {
              pthread_detach (tid);
            }
        }
    }

  shutdown ((int) server_sockfd, SHUT_RDWR);
  close ((int) server_sockfd);
  printf ("\n");
  if (use_syslog)
    {
      syslog (LOG_INFO, "SIGINT received, server shutdown.");
      closelog ();
    }
  else
    printf ("SIGINT received, server shutdown.\n");

  if (chdir (cwd) == -1 && use_syslog)
    syslog (LOG_INFO, "error %m");

  return 0;
}

static void *
sig_int (int sig)
{
  stop = 1;
}

/* service thread per client
   close socket when finished */
static void *
service_client (void *client_sockfd_ptr)
{
  int *client_sockfd = (int *) client_sockfd_ptr;

  /* read HTTP request */
  char buffer[BUFFER_SIZE];
  char ch;
  ssize_t recv_len;
  int i = 0;

  memset (buffer, '\0', BUFFER_SIZE);
  recv_len = recv ((int) client_sockfd, buffer, BUFFER_SIZE, 0);
  buffer[recv_len] = '\0';

  if (recv_len == 0)
    {
      if (use_syslog)
        syslog (LOG_ERR, "client closed connection");

      close ((int) client_sockfd);
      pthread_exit (NULL);
    }
  else if (recv_len == -1)
    {
      if (use_syslog)
        syslog (LOG_ERR, "error receiving data: %m");

      shutdown ((int) client_sockfd, SHUT_RDWR);
      close ((int) client_sockfd);
      pthread_exit (NULL);
    }

  /* get current time */
  char timestamp[32];
  time_t now = time (NULL);
  strftime (timestamp, sizeof timestamp, "%a %d %b %Y %T %Z",
            localtime (&now));

  /* get peer address */
  struct sockaddr_storage client_ss;
  socklen_t client_len = sizeof client_ss;
  char peer[NI_MAXHOST];
  getpeername ((int) client_sockfd, (struct sockaddr *) &client_ss,
               &client_len);
  getnameinfo ((struct sockaddr *) &client_ss, client_len, peer, sizeof peer,
               NULL, 0, NI_NUMERICHOST);

  /* process the request */
  char *saveptr;
  char *method = (char *) strtok_r (buffer, " ", &saveptr);
  char *URL = (char *) strtok_r (NULL, " ", &saveptr);
  char *version = (char *) strtok_r (NULL, "\r\n", &saveptr);

  char header[HEADER_MAX];
  char file[PATH_MAX];
  ssize_t xfer_size = 0;

  if (strncmp (method, "GET", 3) == 0)
    {
      /* TCP options = NODELAY || CORK */
      int optval = 1;
      if (setsockopt
          ((int) client_sockfd, IPPROTO_TCP, TCP_NODELAY, &optval,
           sizeof optval) == -1)
        {
          if (use_syslog)
            syslog (LOG_INFO, "error setting TCP_NODELAY: %m");
        }

      if (setsockopt
          ((int) client_sockfd, IPPROTO_TCP, TCP_CORK, &optval,
           sizeof optval) == -1)
        {
          if (use_syslog)
            syslog (LOG_INFO, "error setting TCP_CORK: %m");
        }

      unescape (URL);
      snprintf (file, (sizeof file) - 1, "%s/%s", basedir, URL);
      file[PATH_MAX - 1] = '\0';
      int fd = open (file, O_RDONLY);
      if (fd == -1)
        {
          switch (errno)
            {
            case EACCES:        /* 403 Forbidden */
              snprintf (header, (sizeof header - 1),
                        "%s 403 Forbidden\r\n\r\n<html><body><h1>403 Forbidden</h1><hr>%s</body></html>",
                        version, SERVER_VERSION);
              header[(sizeof header) - 1] = '\0';
              xfer_size =
                send ((int) client_sockfd, header, strlen (header), 0);
              if (use_syslog)
                syslog (LOG_INFO, "%s %s %s %s 403 Forbidden %d", peer,
                        method, URL, version, xfer_size);
              break;
            case ENOENT:        /* 404 Not Found */
              snprintf (header, (sizeof header - 1),
                        "%s 404 Not Found\r\n\r\n<html><body><h1>404 Not Found</h1><hr>%s</body></html>",
                        version, SERVER_VERSION);
              header[(sizeof header) - 1] = '\0';
              xfer_size =
                send ((int) client_sockfd, header, strlen (header), 0);
              if (use_syslog)
                syslog (LOG_INFO, "%s %s %s %s 404 Not Found %d", peer,
                        method, URL, version, xfer_size);
              break;
            default:            /* 400 Bad Request */
              snprintf (header, (sizeof header - 1),
                        "%s 400 Bad Request\r\n\r\n<html><body><h1>400 Bad Request</h1><hr>%s</body></html>",
                        version, SERVER_VERSION);
              header[(sizeof header) - 1] = '\0';
              xfer_size =
                send ((int) client_sockfd, header, strlen (header), 0);
              if (use_syslog)
                syslog (LOG_INFO, "%s %s %s %s 400 Bad Request %d", peer,
                        method, URL, version, xfer_size);
            }
        }
      else
        {
          struct stat file_stat;
          fstat (fd, &file_stat);
          if (S_ISREG (file_stat.st_mode))
            {
              snprintf (header, (sizeof header - 1),
                        "%s 200 OK\r\nDate: %s\r\nServer: %s\r\nContent-Type: %s\r\nContent-Length: %llu\r\n\r\n",
                        version, timestamp, SERVER_VERSION,
                        get_mime_type (URL), (uint64_t) file_stat.st_size);
              header[(sizeof header) - 1] = '\0';
              send ((int) client_sockfd, header, strlen (header), 0);

              off_t offset = 0;
              uint64_t total_xfer = 0;

              do
                {
                  xfer_size =
                    sendfile ((int) client_sockfd, fd, &offset, CHUNK_SIZE);
                  if (xfer_size == -1)
                    {
                      if (use_syslog)
                        syslog (LOG_INFO, "Error transfer data: %m");

                      break;
                    }
                  else if ((xfer_size != CHUNK_SIZE)
                           && (xfer_size < (file_stat.st_size - total_xfer)))
                    {
                      /* client termination */
                      total_xfer += xfer_size;
                      break;
                    }
                  else
                    {
                      total_xfer += xfer_size;
                    }
                }
              while (total_xfer < file_stat.st_size);

              if (use_syslog)
                syslog (LOG_INFO, "%s %s %s %s 200 OK %llu", peer,
                        method, URL, version, total_xfer);
            }
          else if (S_ISDIR (file_stat.st_mode))
            {
              /* index.html exists ? */
              snprintf (file, (sizeof file) - 1, "%s/index.html", basedir);
              file[(sizeof file) - 1] = '\0';
              int index_fd = open (file, O_RDONLY);
              if (index_fd == -1)
                {
                  if (use_dir_index)
                    {
                      char *index_page = get_index_page (URL);

                      if (index_page == NULL)
                        {
                          snprintf (header, (sizeof header) - 1,
                                    "%s 503 Service Unavailable\r\n\r\n<html><body><h1>503 Service Unavailable</h1><hr>%s</body></html>",
                                    version, SERVER_VERSION);
                          header[(sizeof header) - 1] = '\0';
                          xfer_size =
                            send ((int) client_sockfd, header,
                                  strlen (header), 0);
                          if (use_syslog)
                            syslog (LOG_INFO,
                                    "%s %s %s %s 503 Service Unavailable %d",
                                    peer, method, URL, version, xfer_size);
                        }
                      else
                        {
                          snprintf (header, (sizeof header) - 1,
                                    "%s 200 OK\r\nDate: %s\r\nServer: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n",
                                    version, timestamp, SERVER_VERSION,
                                    "text/html", strlen (index_page));
                          header[(sizeof header) - 1] = '\0';
                          send ((int) client_sockfd, header, strlen (header),
                                0);
                          xfer_size =
                            send ((int) client_sockfd, index_page,
                                  strlen (index_page), 0);

                          if (use_syslog)
                            syslog (LOG_INFO, "%s %s %s %s 200 OK %d",
                                    peer, method, URL, version, xfer_size);

                          free (index_page);
                        }
                    }
                  else
                    {
                      snprintf (header, (sizeof header - 1),
                                "%s 404 Not Found\r\n\r\n<html><body><h1>404 Not Found</h1><hr>%s</body></html>",
                                version, SERVER_VERSION);
                      header[(sizeof header) - 1] = '\0';
                      xfer_size =
                        send ((int) client_sockfd, header, strlen (header),
                              0);
                      if (use_syslog)
                        syslog (LOG_INFO, "%s %s %s %s 404 Not Found %d",
                                peer, method, URL, version, xfer_size);
                    }
                }
              else
                {
                  struct stat index_file_stat;
                  fstat (index_fd, &index_file_stat);
                  snprintf (header, (sizeof header) - 1,
                            "%s 200 OK\r\nDate: %s\r\nServer: %s\r\nContent-Type: text/html\r\nContent-Length: %llu\r\n\r\n",
                            version, timestamp, SERVER_VERSION,
                            (uint64_t) index_file_stat.st_size);
                  header[(sizeof header) - 1] = '\0';
                  send ((int) client_sockfd, header, strlen (header), 0);
                  off_t offset = 0;
                  xfer_size =
                    sendfile ((int) client_sockfd, index_fd, &offset,
                              index_file_stat.st_size);
                  if (use_syslog)
                    syslog (LOG_INFO, "%s %s %s %s 200 OK %d", peer,
                            method, URL, version, xfer_size);
                  close (index_fd);
                }
            }
          close (fd);
        }
    }
  else if (strcmp (method, "HEAD") == 0)
    {
      snprintf (header, (sizeof header) - 1,
                "%s 200 OK\r\nDate: %s\r\nServer: %s\r\n\r\n", version, timestamp,
                SERVER_VERSION);
      header[(sizeof header) - 1] = '\0';
      xfer_size = send ((int) client_sockfd, header, strlen (header), 0);
      if (use_syslog)
        syslog (LOG_INFO, "%s %s %s %s 200 OK %d", peer, method, URL,
                version, xfer_size);
    }
  else
    {
      /* 501 Not Implemented */
      snprintf (header, (sizeof header) - 1,
                "%s 501 Not Implemented\r\nDate: %sServer: %s\r\n\r\n<html><body><h1>501 Not Implemented</h1><hr>%s</body></html>",
                version, timestamp, SERVER_VERSION, SERVER_VERSION);
      header[(sizeof header) - 1] = '\0';
      xfer_size = send ((int) client_sockfd, header, strlen (header), 0);
      if (use_syslog)
        syslog (LOG_INFO, "%s %s %s %s 501 Not Implemented %d", peer,
                method, URL, version, xfer_size);
    }

  shutdown ((int) client_sockfd, SHUT_RDWR);
  close ((int) client_sockfd);
  pthread_exit (NULL);
}

/* 
 * get_index_page from path
 * return char pointer to index page
 * */

static char *
get_index_page (char *orig_URL)
{
  struct dirent **dir_entry;
  char path[PATH_MAX];
  char URL[URL_MAX];
  int n;

  if (URL == NULL)
    return NULL;

  memset (URL, '\0', sizeof URL);
  strncpy (URL, orig_URL, strlen (orig_URL));
  if (URL[strlen (URL) - 1] == '/')
    URL[strlen (URL) - 1] = '\0';

  memset (path, '\0', sizeof path);
  snprintf (path, (sizeof path) - 1, "%s%s", basedir, URL);
  path[(sizeof path) - 1] = '\0';
  if ((n = scandir (path, &dir_entry, 0, alphasort)) == -1)
    {
      if (use_syslog)
        syslog (LOG_INFO, "error scanning directory: %m");

      return NULL;
    }
  else
    {
      char *index_page = (char *) malloc (512000);

      if (index_page == NULL)
        {
          if (use_syslog)
            syslog (LOG_INFO, "error creating index page: %m");

          return NULL;
        }
      else
        {
          char *ptr = index_page;
          int i, l;

          l =
            snprintf (ptr, 512,
                      "<html><title>Index of %s/</title><body><h1>Index of %s/</h1><pre>",
                      URL, URL);
          ptr += (l * sizeof (char));

          for (i = 0; i < n; i++)
            {
              char filename[PATH_MAX];
              struct stat file_stat;

              snprintf (filename, (sizeof filename) - 1, "%s/%s", path,
                        dir_entry[i]->d_name);
              filename[(sizeof filename) - 1] = '\0';
              if (stat (filename, &file_stat) == -1)
                {
                  if (use_syslog)
                    syslog (LOG_INFO, "error stat file %s: %m", filename);
                }
              else
                {
                  if ((dir_entry[i]->d_name[0] == '.')
                      && (dir_entry[i]->d_name[1] != '.')
                      && (dir_entry[i]->d_name[1] != '\0'))
                    continue;

                  char last_modified[32];
                  struct tm result;
                  strftime (last_modified, sizeof last_modified,
                            "%F %T %Z", localtime_r (&file_stat.st_mtime, &result));
                  if (S_ISREG (file_stat.st_mode))
                    {
                      int spaces = 40 - strlen (dir_entry[i]->d_name);
                      spaces = (spaces < 1 ? 1 : spaces);
                      l =
                        snprintf (ptr, 256,
                                  "[   ] <a href=\"%s/%s\">%-.39s</a>%*s%s %llu\n",
                                  URL, dir_entry[i]->d_name,
                                  dir_entry[i]->d_name, spaces, " ",
                                  last_modified,
                                  (uint64_t) file_stat.st_size);
                      ptr += (l * sizeof (char));
                    }
                  else if (S_ISDIR (file_stat.st_mode))
                    {
                      int spaces = 40 - strlen (dir_entry[i]->d_name);
                      spaces = (spaces < 1 ? 1 : spaces);
                      l =
                        snprintf (ptr, 256,
                                  "[DIR] <a href=\"%s/%s\">%-.39s</a>%*s%s -\n",
                                  URL, dir_entry[i]->d_name,
                                  dir_entry[i]->d_name, spaces, " ",
                                  last_modified);
                      ptr += (l * sizeof (char));
                    }

                }
            }

          l =
            snprintf (ptr, 48, "</pre><hr>%s</body></html>", SERVER_VERSION);
          ptr += (l * sizeof (char));

          free (dir_entry);
          return index_page;
        }
    }
}

/* get mime type from file extension
   if unknown, fallback to octet-stream */
static char *
get_mime_type (char *fname)
{
  char *ext = strrchr (fname, '.');

  if (ext == NULL)
    return "application/octet-stream";

  /* Applications */
  if (strcasecmp (ext, ".odt") == 0)
    return "application/vnd.oasis.opendocument.text";
  if (strcasecmp (ext, ".ott") == 0)
    return "application/vnd.oasis.opendocument.text-template";
  if (strcasecmp (ext, ".odg") == 0)
    return "application/vnd.oasis.opendocument.graphics";
  if (strcasecmp (ext, ".otg") == 0)
    return "application/vnd.oasis.opendocument.graphics-template";
  if (strcasecmp (ext, ".odp") == 0)
    return "application/vnd.oasis.opendocument.presentation";
  if (strcasecmp (ext, ".otp") == 0)
    return "application/vnd.oasis.opendocument.presentation-template";
  if (strcasecmp (ext, ".ods") == 0)
    return "application/vnd.oasis.opendocument.spreadsheet";
  if (strcasecmp (ext, ".ots") == 0)
    return "application/vnd.oasis.opendocument.spreadsheet-template";
  if (strcasecmp (ext, ".odc") == 0)
    return "application/vnd.oasis.opendocument.chart";
  if (strcasecmp (ext, ".otc") == 0)
    return "application/vnd.oasis.opendocument.chart-template";
  if (strcasecmp (ext, ".odi") == 0)
    return "application/vnd.oasis.opendocument.image";
  if (strcasecmp (ext, ".oti") == 0)
    return "application/vnd.oasis.opendocument.image-template";
  if (strcasecmp (ext, ".odf") == 0)
    return "application/vnd.oasis.opendocument.formula";
  if (strcasecmp (ext, ".otf") == 0)
    return "application/vnd.oasis.opendocument.formula-template";
  if (strcasecmp (ext, ".odm") == 0)
    return "application/vnd.oasis.opendocument.text-master";
  if (strcasecmp (ext, ".oth") == 0)
    return "application/vnd.oasis.opendocument.text-web";
  if (strcasecmp (ext, ".sxw") == 0)
    return "application/vnd.sun.xml.writer";
  if (strcasecmp (ext, ".sxw") == 0)
    return "application/vnd.sun.xml.writer.template";
  if (strcasecmp (ext, ".sxw") == 0)
    return "application/vnd.sun.xml.writer.global";
  if (strcasecmp (ext, ".sxw") == 0)
    return "application/vnd.sun.xml.calc";
  if (strcasecmp (ext, ".sxw") == 0)
    return "application/vnd.sun.xml.calc.template";
  if (strcasecmp (ext, ".sxw") == 0)
    return "application/vnd.sun.xml.impress";
  if (strcasecmp (ext, ".sxw") == 0)
    return "application/vnd.sun.xml.impress.template";
  if (strcasecmp (ext, ".sxw") == 0)
    return "application/vnd.sun.xml.draw";
  if (strcasecmp (ext, ".sxw") == 0)
    return "application/vnd.sun.xml.draw.template";
  if (strcasecmp (ext, ".sxw") == 0)
    return "application/vnd.sun.xml.math";
  if (strcasecmp (ext, ".doc") == 0)
    return "application/msword";
  if (strcasecmp (ext, ".xls") == 0)
    return "application/vnd.ms-excel";
  if (strcasecmp (ext, ".ppt") == 0)
    return "application/vnd.ms-powerpoint";
  if (strcasecmp (ext, ".pdf") == 0)
    return "application/pdf";
  if (strcasecmp (ext, ".dvi") == 0)
    return "application/x-dvi";
  if (strcasecmp (ext, ".tex") == 0)
    return "application/x-tex";

  /* archive */
  if (strcasecmp (ext, ".tar") == 0)
    return "application/x-tar";
  if (strcasecmp (ext, ".zip") == 0)
    return "application/zip";
  if (strcasecmp (ext, ".rar") == 0)
    return "application/x-rar-compressed";

  /* text */
  if ((strcasecmp (ext, ".htm") == 0) || (strcasecmp (ext, ".html") == 0))
    return "text/html";
  if (strcasecmp (ext, ".css") == 0)
    return "text/css";
  if (strcasecmp (ext, ".xml") == 0)
    return "text/xml";
  if ((strcasecmp (ext, ".txt") == 0) || (strcasecmp (ext, ".asc") == 0)
      || (strcasecmp (ext, ".c") == 0) || (strcasecmp (ext, ".cpp") == 0)
      || (strcasecmp (ext, ".h") == 0) || (strcasecmp (ext, ".hh") == 0)
      || (strcasecmp (ext, ".f") == 0) || (strcasecmp (ext, ".f90") == 0))
    return "text/plain";
  if (strcasecmp (ext, ".rtf") == 0)
    return "text/rtf";

  /* images */
  if ((strcasecmp (ext, ".jpg") == 0) || (strcasecmp (ext, ".jpeg") == 0))
    return "image/jpeg";
  if ((strcasecmp (ext, ".tif") == 0) || (strcasecmp (ext, ".tiff") == 0))
    return "image/tiff";
  if (strcasecmp (ext, ".gif") == 0)
    return "image/gif";
  if (strcasecmp (ext, ".png") == 0)
    return "image/png";

  /* video */
  if (strcasecmp (ext, ".avi") == 0)
    return "video/x-msvideo";
  if (strcasecmp (ext, ".wmv") == 0)
    return "video/x-ms-wmv";
  if ((strcasecmp (ext, ".mpg") == 0) || (strcasecmp (ext, ".mpeg") == 0)
      || (strcasecmp (ext, ".mpe") == 0))
    return "video/mpeg";
  if (strcasecmp (ext, ".ogv") == 0)
    return "video/ogg";
  if (strcasecmp (ext, ".mkv") == 0)
    return "video/x-matroska";
  if ((strcasecmp (ext, ".mp4") == 0) || (strcasecmp (ext, ".f4v") == 0)
      || (strcasecmp (ext, ".f4p") == 0))
    return "video/mp4";
  if ((strcasecmp (ext, ".mov") == 0) || (strcasecmp (ext, ".qt") == 0))
    return "video/quicktime";
  if (strcasecmp (ext, ".swf") == 0)
    return "application/x-shockwave-flash";
  if (strcasecmp (ext, ".flv") == 0)
    return "video/x-flv";

  /* audio */
  if (strcasecmp (ext, ".wav") == 0)
    return "audio/x-wav";
  if (strcasecmp (ext, ".wma") == 0)
    return "audio/x-ms-wma";
  if ((strcasecmp (ext, ".mp3") == 0) || (strcasecmp (ext, ".mp2") == 0))
    return "audio/mpeg";
  if ((strcasecmp (ext, ".m4a") == 0) || (strcasecmp (ext, ".m4b") == 0)
      || (strcasecmp (ext, ".f4a") == 0) || (strcasecmp (ext, ".f4b") == 0))
    return "audio/mp4";
  if ((strcasecmp (ext, ".oga") == 0) || (strcasecmp (ext, ".ogg") == 0))
    return "audio/ogg";

  /* fallback */
  return "application/octet-stream";
}

/* unescape string
 * based on HTUnEscape () in HTEscape.c of libwww 
 * under W3C license */
static void
unescape (char *str)
{
  char *p = str;

  while (*str) 
    {
      if (*str == '%')
        {
          if (*++str)
            *p = hex (*str) * 16;
          if (*++str)
            *p++ += hex (*str);
        }
      else
        *p++ = *str;

      str++;
    }
  *p = 0;
}

/* convert single hex character to integer */
static inline unsigned char
hex (char c)
{
  return c >= '0' && c <= '9' ? c - '0' 
         : c >= 'A' && c <= 'F' ? c - 'A' + 10 
         : c - 'a' + 10;
}

static void
help (char *progname)
{
  printf ("Usage %-.32s [OPTION...]\n", progname);
  printf ("A lightweight web server.\n");
  printf ("\n");
  printf ("  -6, --v6only                    use IPv6 only\n");
  printf ("  -d, --docroot=, --path=PATH     set document root to PATH \n");
  printf ("  -i, --index                     use automatic indexing\n");
  printf ("  -p, --port=NUM                  listen on port NUM (default 8080)\n");
  printf ("  -l, --log                       log to syslog\n");
  printf ("  -r, --reuseaddr                 attempt to set SO_REUSEADDR\n");
  printf ("  -u, --user=USERNAME             use user USERNAME to run the server\n");
  printf ("  -v, --version                   show version\n");
  printf ("  -h, --help                      print this help\n");
  printf ("\n");
  printf ("Report bugs to kitty@kitty.in.th\n");
  printf ("\n");
}
