/* 
kitty-httpd.c 
A small-footprint, low-feature web server.

v. 0.0.4
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
	As of Fri, 24 Jul 2009 20:22:05 +0700, none.

To Do
-----
	- Use chroot option
	- Set uid/gid option
	- Default favicon.ico
	- Log to file option
	- Foreground & background mode
	- IPv6 supported
	- Secure programming
	- Code optimization
	- Network optimization
	- Beautify the index page + CSS

Not-so-near-future To Do
------------------------
	- GNOME Notification Area

*/

#define _FILE_OFFSET_BITS 64
#define __USE_LARGEFILE64 1
#define __USE_FILE_OFFSET64 1
#define CHUNKSIZE 1073741824

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
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define BACKLOG 16
#define BUFFER_LEN 1024
#define SERVER_VERSION "Kitty-HTTPD/0.0.4"

static void *sig_int (int);
static void *service_client (void *);
static char *get_index_page (char *);
static char *get_mime_type (char *);
void unescape (char *);
static int hex (char);

char basedir[256];
int stop = 0;

int nth = 0;

int
main (int argc, char *argv[])
{
	int server_sockfd;
	struct sockaddr_in server_addr;
	int server_port = 8080;
	int use_ipv6 = 0;
	int use_so_reuseaddr= 0;
	int opt;
	strcpy (basedir, ".");

	/* parse argument */
	while ((opt = getopt (argc, argv, "d:p:6rh")) != -1)
		{
			switch (opt)
				{
				case 'd':
					strcpy (basedir, optarg);
					break;
				case 'p':
					server_port = atoi (optarg);
					break;
				case '6':
					use_ipv6 = 1;
					break;
				case 'r':
					use_so_reuseaddr = 1;
					break;
				case 'h':
					printf ("Usage: %s [-d directory] [-p port]\n", argv[0]);
					exit (EXIT_SUCCESS);
				default:
					exit (EXIT_FAILURE);
				}
		}

	/* test basedir */
	int bd;
	if ((bd = open (basedir, O_RDONLY)) == -1)
		{
			perror ("Error opening base directory");
			exit (EXIT_FAILURE);
		}
	else
		{
			close (bd);
		}
	/* signal handler */
	signal (SIGINT, (void *) sig_int);
	siginterrupt (SIGINT, 1);

	/* create socket */
	if ((server_sockfd = socket (PF_INET, SOCK_STREAM, 0)) == -1)
		{
			perror ("Error opening socket");
			exit (EXIT_FAILURE);
		}

	/* create a socket */
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons (server_port);
	server_addr.sin_addr.s_addr = htonl (INADDR_ANY);

	/* set SO_REUSEADDR if specified */
	if (use_so_reuseaddr)
		{
			int optval = 1;
			if (setsockopt (server_sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval) == -1)
				{
					perror ("Error setting SO_REUSEADDR");
				}
		}

	/* bind port */
	if ((bind
			 (server_sockfd, (const struct sockaddr *) &server_addr,
				sizeof server_addr)) == -1)
		{
			perror ("Error binding port");
			exit (EXIT_FAILURE);
		}

	/* listen */
	if (listen (server_sockfd, BACKLOG) == -1)
		{
			perror ("Error listening for connections");
			exit (EXIT_FAILURE);
		}

	printf ("Server successfully started at port %d.\nBase directory = %s.\n",
					server_port, basedir);

	/* main loop - accept a connection, thread out service function */
	while (!stop)
		{
			int client_sockfd;
			struct sockaddr_in client_addr;
			socklen_t client_addr_len = sizeof client_addr;

			if ((client_sockfd = accept (server_sockfd, (struct sockaddr *) &client_addr, &client_addr_len)) != -1)
				{	
					pthread_t tid;

					if (pthread_create (&tid, NULL, service_client, (void *) client_sockfd))
						{
							perror ("Error creating service thread");
						}
					else
						{
							pthread_detach (tid);
						}
				}
		}

	shutdown ((int) server_sockfd, SHUT_RDWR);
	printf ("\nSIGINT received. Server shutdown.\n");

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
	char buffer[BUFFER_LEN];
	char ch;
	ssize_t recv_len;
	int i = 0;

	while (((recv_len = recv ((int) client_sockfd, (void *) &ch, 1, 0)) > 0)
				 && i < BUFFER_LEN)
		{
			if (ch == '\r')
				{
					continue;
				}
			else
				{
					buffer[i] = ch;
					i++;
					if (ch == '\n')
						{
							break;
						}
				}
		}

	if (recv_len == 0)
		{
			printf ("Client closed connection\n");
			close ((int) client_sockfd);
			pthread_exit (NULL);
		}
	else if (recv_len == -1)
		{
			perror ("Error receiving data");
			close ((int) client_sockfd);
			pthread_exit (NULL);
		}

	/* get current time */
	char timestamp[128];
	time_t now;
	struct tm *now_tm;
	now = time (NULL);
	now_tm = localtime (&now);
	strftime (timestamp, sizeof timestamp, "%a, %d %b %Y %H:%M:%S %Z", now_tm);

	/* get peer address */
	struct sockaddr_in client;
	socklen_t client_len = sizeof client;
	getpeername ((int) client_sockfd, (struct sockaddr *) &client, &client_len);

	/* process the request */
	char *method = (char *) strtok (buffer, " ");
	char *URL = (char *) strtok (NULL, " ");
	char *version = (char *) strtok (NULL, " \n");

	char header[256];
	char file[256];
	ssize_t xfer_size = 0;

	if (strcmp (method, "GET") == 0)
		{
			/* TCP options = NODELAY || CORK */
			int optval = 1;
			if (setsockopt ((int) client_sockfd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof optval) == -1)
				{
					perror ("Error seting TCP_NODELAY");
				}

			if (setsockopt ((int) client_sockfd, IPPROTO_TCP, TCP_CORK, &optval, sizeof optval) == -1)
				{
					perror ("Error seting TCP_CORK");
				}

			unescape (URL);
			sprintf (file, "%s/%s", basedir, URL);
			int fd = open (file, O_RDONLY);
			if (fd == -1)
				{
					switch (errno)
						{
						case EACCES:				/* 403 Forbidden */
							sprintf (header,
											 "%s 403 Forbidden\n\n<html><body><h1>403 Forbidden</h1><hr>%s</body></html>",
											 version, SERVER_VERSION);
							xfer_size =
								send ((int) client_sockfd, header, strlen (header), 0);
							printf ("%s: %s %s %s %s 403 Forbidden %d\n", timestamp,
											inet_ntoa (client.sin_addr), method, URL, version,
											xfer_size);
							break;
						case ENOENT:				/* 404 Not Found */
							sprintf (header,
											 "%s 404 Not Found\n\n<html><body><h1>404 Not Found</h1><hr>%s</body></html>",
											 version, SERVER_VERSION);
							xfer_size =
								send ((int) client_sockfd, header, strlen (header), 0);
							printf ("%s: %s %s %s %s 404 Not Found %d\n", timestamp,
											inet_ntoa (client.sin_addr), method, URL, version,
											xfer_size);
							break;
						default:						/* 400 Bad Request */
							sprintf (header,
											 "%s 400 Bad Request\n\n<html><body><h1>400 Bad Request</h1><hr>%s</body></html>",
											 version, SERVER_VERSION);
							xfer_size =
								send ((int) client_sockfd, header, strlen (header), 0);
							printf ("%s: %s %s %s %s 400 Bad Request %d\n", timestamp,
											inet_ntoa (client.sin_addr), method, URL, version,
											xfer_size);
						}
				}
			else
				{
					struct stat file_stat;
					fstat (fd, &file_stat);
					if (S_ISREG (file_stat.st_mode))
						{
							sprintf (header,
											 "%s 200 OK\nDate: %s\nServer: %s\nContent-Type: %s\nContent-Length: %llu\n\n",
											 version, timestamp, SERVER_VERSION,
											 get_mime_type (URL), (uint64_t) file_stat.st_size);
							send ((int) client_sockfd, header, strlen (header), 0);
							off_t offset = 0;
							uint64_t total_xfer = 0;

							do 
								{
									xfer_size = sendfile ((int) client_sockfd, fd, &offset, CHUNKSIZE);
									if (xfer_size == -1)
										{
											perror ("Error transfer data");
											break;
										}
									else if ((xfer_size != CHUNKSIZE) && (xfer_size < (file_stat.st_size - total_xfer)))
										{
											// client termination 
											total_xfer += xfer_size;
											break;
										}
									else
										{
											total_xfer += xfer_size;
										}
								}
							while (total_xfer < file_stat.st_size);

							printf ("%s: %s %s %s %s 200 OK %llu\n", timestamp,
											inet_ntoa (client.sin_addr), method, URL, version,
											total_xfer);
						}
					else if (S_ISDIR (file_stat.st_mode))
						{
							/* index.html exists ? */
							sprintf (file, "%s/index.html", basedir);
							int index_fd = open (file, O_RDONLY);
							if (index_fd == -1)
								{
									char *index_page = get_index_page (URL);

									if (index_page == NULL)
										{
											sprintf (header,
															 "%s 500 Internal Server Error\n\n<html><body><h1>500 Internal Server Error</h1><hr>%s</body></html>",
															 version, SERVER_VERSION);
											xfer_size =
												send ((int) client_sockfd, header, strlen (header),
															0);
											printf
												("%s: %s %s %s %s 500 Internal Server Error %d\n",
												 timestamp, inet_ntoa (client.sin_addr), method, URL,
												 version, xfer_size);
										}
									else
										{
											sprintf (header,
															 "%s 200 OK\nDate: %s\nServer: %s\nContent-Type: %s\nContent-Length: %d\n\n",
															 version, timestamp, SERVER_VERSION,
															 "text/html", strlen (index_page));
											send ((int) client_sockfd, header, strlen (header), 0);
											xfer_size =
												send ((int) client_sockfd, index_page,
															strlen (index_page), 0);

											printf ("%s: %s %s %s %s 200 OK %d\n", timestamp,
															inet_ntoa (client.sin_addr), method, URL,
															version, xfer_size);

											free (index_page);
										}
								}
							else
								{
									struct stat index_file_stat;
									fstat (index_fd, &index_file_stat);
									sprintf (header,
													 "%s 200 OK\nDate: %s\nServer: %s\nContent-Type: text/html\nContent-Length: %llu\n\n",
													 version, timestamp, SERVER_VERSION,
													 (uint64_t) index_file_stat.st_size);
									send ((int) client_sockfd, header, strlen (header), 0);
									off_t offset = 0;
									xfer_size =
										sendfile ((int) client_sockfd, index_fd, &offset,
															index_file_stat.st_size);

									printf ("%s: %s %s %s %s 200 OK %d\n", timestamp,
													inet_ntoa (client.sin_addr), method, URL, version,
													xfer_size);
									close (index_fd);
								}
						}
					close (fd);
				}
		}
	else if (strcmp (method, "HEAD") == 0)
		{
			sprintf (header, "%s 200 OK\nDate: %s\nServer: %s\n\n", version,
							 timestamp, SERVER_VERSION);
			xfer_size = send ((int) client_sockfd, header, strlen (header), 0);
			printf ("%s: %s %s %s %s 200 OK %d\n", timestamp,
							inet_ntoa (client.sin_addr), method, URL, version, xfer_size);
		}
	else
		{
			/* 501 Not Implemented */
			sprintf (header,
							 "%s 501 Not Implemented\nDate: %sServer: %s\n\n<html><body><h1>501 Not Implemented</h1><hr>%s</body></html>",
							 version, timestamp, SERVER_VERSION, SERVER_VERSION);
			xfer_size = send ((int) client_sockfd, header, strlen (header), 0);
			printf ("%s: %s %s %s %s 501 Not Implemented %d\n", timestamp,
							inet_ntoa (client.sin_addr), method, URL, version, xfer_size);
		}

	shutdown ((int) client_sockfd, SHUT_RDWR);
	pthread_exit (NULL);
}

/* 
 * get_index_page from path
 * return char pointer to index page
 * */

static char *
get_index_page (char *URL)
{
	struct dirent **dir_entry;
	char path[256];
	int n;

	if (URL == NULL)
		return NULL;

	if (URL[strlen (URL) - 1] == '/')
		URL[strlen (URL) - 1] = '\0';


	sprintf (path, "%s%s", basedir, URL);
	if ((n = scandir (path, &dir_entry, 0, alphasort)) == -1)
		{
			perror ("Error scanning directory");
			return NULL;
		}
	else
		{
			char *index_page = (char *) malloc (512000);

			if (index_page == NULL)
				{
					perror ("Error creating index page");
					return NULL;
				}
			else
				{
					char *ptr = index_page;
					int i, l;

					l =
						sprintf (ptr,
										 "<html><title>Index of %s/</title><body><h1>Index of %s/</h1><table>",
										 URL, URL);
					ptr += (l * sizeof (char));

					for (i = 0; i < n; i++)
						{
							char filename[512];
							struct stat file_stat;

							sprintf (filename, "%s/%s", path, dir_entry[i]->d_name);
							if (stat (filename, &file_stat) == -1)
								{
									perror ("Error stat file");
									return NULL;
								}
							else
								{
									char last_modified[32];
									struct tm *last_modified_tm =
										localtime (&file_stat.st_mtime);
									strftime (last_modified, sizeof last_modified,
														"%F %H:%M:%S %z", last_modified_tm);
									if (S_ISREG (file_stat.st_mode))
										{
											l =
												sprintf (ptr,
																 "<tr><td>[FILE]</td><td><a href=\"%s/%s\">%s</a></td><td>%s</td><td>%llu</td></tr>\n",
																 URL, dir_entry[i]->d_name,
																 dir_entry[i]->d_name, last_modified,
																 (uint64_t) file_stat.st_size);
											ptr += (l * sizeof (char));
										}
									else if (S_ISDIR (file_stat.st_mode))
										{
											l =
												sprintf (ptr,
																 "<tr><td>[DIR]</td><td><a href=\"%s/%s\">%s</a></td><td>%s</td><td>-</td></tr>\n",
																 URL, dir_entry[i]->d_name,
																 dir_entry[i]->d_name, last_modified);
											ptr += (l * sizeof (char));
										}

								}
						}

					l = sprintf (ptr, "</table><hr>%s</body></html>", SERVER_VERSION);
					ptr += (l * sizeof (char));

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
	if (strcasecmp (ext, ".swf") == 0)
		return "application/x-shockwave-flash";
	if (strcasecmp (ext, ".tex") == 0)
		return "application/x-tex";
	if (strcasecmp (ext, ".tar") == 0)
		return "application/x-tar";
	if (strcasecmp (ext, ".zip") == 0)
		return "application/zip";
	if (strcasecmp (ext, ".rar") == 0)
		return "application/x-rar-compressed";
	if ((strcasecmp (ext, ".ogg") == 0) || (strcasecmp (ext, ".ogm") == 0))
		return "application/ogg";

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

	if ((strcasecmp (ext, ".jpg") == 0) || (strcasecmp (ext, ".jpeg") == 0))
		return "image/jpeg";
	if ((strcasecmp (ext, ".tif") == 0) || (strcasecmp (ext, ".tiff") == 0))
		return "image/tiff";
	if (strcasecmp (ext, ".gif") == 0)
		return "image/gif";
	if (strcasecmp (ext, ".png") == 0)
		return "image/png";

	if (strcasecmp (ext, ".avi") == 0)
		return "video/x-msvideo";
	if (strcasecmp (ext, ".wmv") == 0)
		return "video/x-ms-wmv";
	if ((strcasecmp (ext, ".mpg") == 0) || (strcasecmp (ext, ".mpeg") == 0)
			|| (strcasecmp (ext, "mpe") == 0))
		return "video/mpeg";
	if (strcasecmp (ext, ".mkv") == 0)
		return "video/x-matroska";
	if (strcasecmp (ext, ".mp4") == 0)
		return "video/mp4";
	if ((strcasecmp (ext, ".mov") == 0) || (strcasecmp (ext, ".qt") == 0))
		return "video/quicktime";

	if (strcasecmp (ext, ".wav") == 0)
		return "audio/x-wav";
	if (strcasecmp (ext, ".wma") == 0)
		return "video/x-ms-wma";
	if ((strcasecmp (ext, ".mp3") == 0) || (strcasecmp (ext, ".mp2") == 0))
		return "audio/mpeg";

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

	return "application/octet-stream";
}

/* unescape string
 * based on MPL-licensed code in koders.com */
void
unescape (char *s)
{
	char *p;

	for (p = s; *s != '\0'; s++)
		{
			if (*s == '%')
				{
					if (*++s != '\0')
						*p = hex (*s) << 4;
					if (*++s != '\0')
						*p++ += hex (*s);
				}
			else
				*p++ = *s;
		}
	*p = '\0';
}

/* convert single hex character to integer */
static int
hex (char c)
{
	return (c >= '0' && c <= '9' ? c - '0' : c >= 'A'
					&& c <= 'F' ? c - 'A' + 10 : c - 'a' + 10);
}