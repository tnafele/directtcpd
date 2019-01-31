/* This is a sample implementation of a libssh based SSH server */
/*
Copyright 2003-2009 Aris Adamantiadis
Copyright 2018 T. Wimmer

This file is part of the SSH Library

You are free to copy this file, modify it in any way, consider it being public
domain. This does not apply to the rest of the library though, but it is
allowed to cut-and-paste working code from this file to any license of
program.
The goal is to show the API in action. It's not a reference on how terminal
clients must be made or how a client should react.
*/

/*
 gcc -o sshd_direct-tcpip sshd_direct-tcpip.c -ggdb -Wall `pkg-config libssh --libs --cflags` -I./libssh/include/ -I.

 Example:
  ./sshd_direct-tcpip -v -p 2022 -d serverkey.dsa -r serverkey.rsa 127.0.0.1
*/

#include "/home/till/libssh/build/config.h"

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
//#include <libssh/messages.h>
#include <libssh/channels.h>
//#include <libssh/poll.h>

#ifdef HAVE_ARGP_H
#include <argp.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <poll.h>

#ifndef KEYS_FOLDER
#ifdef _WIN32
#define KEYS_FOLDER
#else
#define KEYS_FOLDER "/etc/ssh/"
#endif
#endif

#define USER "user"
#define PASSWORD "pwd"

static int authenticated=0;
static int tries = 0;
static int error = 0;
static int sockets_cnt = 0;
//static ssh_channel chan=NULL;
static ssh_event mainloop=NULL;

struct channel_cfg {
	int socket;
	ssh_channel channel;
	int status_socket;
	int status_channel;
};

static int auth_password(ssh_session session, const char *user,
		const char *password, void *userdata){
	(void)userdata;
	printf("Authenticating user %s pwd %s\n",user, password);
	if(strcmp(user,USER) == 0 && strcmp(password, PASSWORD) == 0){
		authenticated = 1;
		printf("Authenticated\n");
		return SSH_AUTH_SUCCESS;
	}
	if (tries >= 3){
		printf("Too many authentication tries\n");
		ssh_disconnect(session);
		error = 1;
		return SSH_AUTH_DENIED;
	}
	tries++;
	return SSH_AUTH_DENIED;
}

static int auth_gssapi_mic(ssh_session session, const char *user, const char *principal, void *userdata){
	ssh_gssapi_creds creds = ssh_gssapi_get_creds(session);
	(void)userdata;
	printf("Authenticating user %s with gssapi principal %s\n",user, principal);
	if (creds != NULL)
		printf("Received some gssapi credentials\n");
	else
		printf("Not received any forwardable creds\n");
	printf("authenticated\n");
	authenticated = 1;
	return SSH_AUTH_SUCCESS;
}

static int subsystem_request(ssh_session session, ssh_channel channel, const char *subsystem, void *userdata){
	(void)session;
	(void)channel;
	//(void)subsystem;
	(void)userdata;
	printf("Channel subsystem reqeuest: %s\n", subsystem);
	return 0;
}

struct ssh_channel_callbacks_struct channel_cb = {
	.channel_subsystem_request_function = subsystem_request
}; 

static ssh_channel new_session_channel(ssh_session session, void *userdata){
	(void) session;
	(void) userdata;
	printf("Session channel request\n");
	/* For TCP forward only there seems to be no need for a session channel */
	/*if(chan != NULL)
		return NULL;
	printf("Session channel request\n");
	chan = ssh_channel_new(session);
	ssh_callbacks_init(&channel_cb);
	ssh_set_channel_callbacks(chan, &channel_cb);
	return chan;*/
	return NULL;
}

static void close_socket(ssh_session session, int fd) {
	sockets_cnt--;
	printf("Closing fd = %d sockets_cnt = %d\n", fd, sockets_cnt);
	ssh_event_remove_session(mainloop, session);
	ssh_event_remove_fd(mainloop, fd);
	ssh_event_add_session(mainloop, session);
	close(fd);
}

static int service_request(ssh_session session, const char *service, void *userdata){
	(void)session;
	//(void)service;
	(void)userdata;
	printf("Service request: %s\n", service);
	return 0;
}

static void global_request(ssh_session session, ssh_message message, void *userdata){
	(void)session;
	(void)userdata;
	printf("Global request, message type: %d\n", ssh_message_type(message));
}

static void my_channel_close_function(ssh_session session, ssh_channel channel, void *userdata) {
	(void)session;

	int fd = *((int *)userdata);
	printf("Channel %d:%d closed by remote. State=%d\n", channel->local_channel, channel->remote_channel, channel->state);
	
	close_socket(session, fd);

	if (ssh_channel_is_open(channel)) {
		ssh_channel_close(channel);
	}
}

static void my_channel_eof_function(ssh_session session, ssh_channel channel, void *userdata) {
	(void)session;
	//(void)userdata;
	int fd = *((int *)userdata);
	printf("Got EOF on channel %d:%d. Shuting down write on socket (fd = %d).\n", channel->local_channel, channel->remote_channel, fd);

	close_socket(session, fd);
	//if (-1 == shutdown(fd, SHUT_WR)) {
	//	perror("Shutdown socket for writing");
	//}
}

static void my_channel_exit_status_function(ssh_session session, ssh_channel channel, int exit_status, void *userdata) {
	(void)session;
	//(void)userdata;
	int fd = *((int *)userdata);
	printf("Got exit status %d on channel %d:%d fd = %d.\n", exit_status, channel->local_channel, channel->remote_channel, fd);
}

static int my_channel_data_function(ssh_session session, ssh_channel channel, void *data, uint32_t len, int is_stderr, void *userdata) {
	int i = 0;
	int fd = *((int *)userdata);

	printf("%d bytes waiting on channel %d:%d for reading. Fd = %d\n",len, channel->local_channel, channel->remote_channel, fd);
	if (len > 0) {
		i = send(fd, data, len, 0);
	}
	if (i < 0) {
		perror("Writing to tcp socket");
		close_socket(session, fd);
		ssh_channel_send_eof(channel);
	}
	else {
		printf("Sent %d bytes\n", i);
	}
	return i;
}

static int cb_readsock(socket_t fd, int revents, void *userdata) {
	ssh_channel channel = (ssh_channel)userdata;
	ssh_session session;
	int len, i, wr;
	char buf[16384];
	int	blocking;

	if(channel == NULL) {
		fprintf(stderr, "channel == NULL!\n");
		return 0;
	}

	session = ssh_channel_get_session(channel);

	if(ssh_channel_is_closed(channel)) {
		fprintf(stderr, "channel is closed!\n");
		//close_socket(session, fd);
		shutdown(fd, SHUT_WR);
		return 0;
	}

	if(!(revents & POLLIN)) {
		printf("revents != POLLIN:");
        if (revents & POLLPRI) {
            printf(" POLLPRI" );
        }
        if (revents & POLLOUT) {
            printf(" POLLOUT" );
        }
        if (revents & POLLHUP) {
            printf(" POLLHUP" );
        }
        if (revents & POLLNVAL) {
            printf(" POLLNVAL");
        }
        if (revents & POLLERR) {
            printf(" POLLERR");
        }
        //if (revents & POLLRDHUP) {
        //    printf(" POLLRDHUP");
        //}
        printf("\n");
		return 0;
	}

	blocking = ssh_is_blocking(session);
	ssh_set_blocking(session, 0);

	printf("Trying to read from tcp socket fd = %d... (Channel %d:%d state=%d)\n", fd, channel->local_channel, channel->remote_channel, channel->state);
	len = recv(fd, buf, sizeof(buf), 0);
	if (len < 0) {
		perror("Reading from tcp socket");
		//ssh_event_remove_fd(mainloop, fd);
		//close(fd);
		ssh_channel_send_eof(channel);
	}
	else if (len > 0) {
		if (ssh_channel_is_open(channel)) {
			wr = 0;
			do {
				i = ssh_channel_write(channel, buf, len);
				if (i < 0) {
					fprintf(stderr, "Error writing on the direct-tcpip channel: %d\n", i);
					len = wr;
					break;
				}
				wr += i;
				printf("channel_write (%d from %d)\n", wr, len);
			} while (i > 0 && wr < len);
		}
		else {
			fprintf(stderr, "Can't write on closed channel!\n");
		}
	}
	else {
		printf("The destination host has disconnected!\n");

		ssh_channel_close(channel);
		shutdown(fd, SHUT_RD);

	}
	ssh_set_blocking(session, blocking);

	return len;
}

int open_tcp_socket(ssh_message msg) {
	struct sockaddr_in sin;
	int forwardsock = -1;
	struct hostent *host;
	const char *dest_hostname;
	int dest_port;
	
	forwardsock = socket(AF_INET, SOCK_STREAM, 0);
	if (forwardsock < 0) {
		perror("ERROR opening socket");
		return -1;
	}
	
	dest_hostname = ssh_message_channel_request_open_destination(msg);
	dest_port = ssh_message_channel_request_open_destination_port(msg);
	
	printf("Connecting to %s on port %d\n", dest_hostname, dest_port);

	host = gethostbyname(dest_hostname);
	if (host == NULL) {
		fprintf(stderr,"ERROR, no such host: %s\n", dest_hostname);
		return -1;
	}

	bzero((char *) &sin, sizeof(sin));
	sin.sin_family = AF_INET;
	bcopy((char *)host->h_addr, (char *)&sin.sin_addr.s_addr, host->h_length);
	sin.sin_port = htons(dest_port);

	if (connect(forwardsock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("ERROR connecting");
		return -1;
	}

	sockets_cnt++;
	printf("Connected. sockets_cnt = %d\n", sockets_cnt);
	return forwardsock;
}


static int message_callback(ssh_session session, ssh_message message, void *userdata){
	(void)session;
	(void)message;
	(void)userdata;
	ssh_channel channel;
	int *pFd;
	struct ssh_channel_callbacks_struct *cb_chan;

	//int dest_port;
	printf("Message type: %d\n", ssh_message_type(message));
	printf("Message Subtype: %d\n", ssh_message_subtype(message));
	if(ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN) {
		//printf("channel_request_open.sender: %d\n", message->channel_request_open.sender);
		printf("channel_request_open\n");
		
		if (ssh_message_subtype(message) == SSH_CHANNEL_DIRECT_TCPIP) {
			channel = ssh_message_channel_request_open_reply_accept(message);

			//	return 0;
			if (channel == NULL) {
				printf("Accepting direct-tcpip channel failed!\n");
				return 1;
			}
			else {
				printf("Connected to channel!\n");
				pFd = malloc(sizeof(int));
				cb_chan = malloc(sizeof(struct ssh_channel_callbacks_struct));
				
				*pFd = open_tcp_socket(message);
				if (-1 == *pFd) {
					return 1;
				}

				cb_chan->userdata = pFd;
				cb_chan->channel_eof_function = my_channel_eof_function;
				cb_chan->channel_close_function = my_channel_close_function;
				cb_chan->channel_data_function = my_channel_data_function;
				cb_chan->channel_exit_status_function = my_channel_exit_status_function;

				ssh_callbacks_init(cb_chan);
				ssh_set_channel_callbacks(channel, cb_chan);
				
				ssh_event_add_fd(mainloop, (socket_t)*pFd, POLLIN, cb_readsock, channel);

				return 0;
			}
		}
	}
	return 1;
}

#ifdef HAVE_ARGP_H
const char *argp_program_version = "libssh server example "
SSH_STRINGIFY(LIBSSH_VERSION);
const char *argp_program_bug_address = "<libssh@libssh.org>";

/* Program documentation. */
static char doc[] = "libssh -- a Secure Shell protocol implementation";

/* A description of the arguments we accept. */
static char args_doc[] = "BINDADDR";

/* The options we understand. */
static struct argp_option options[] = {
	{
		.name  = "port",
		.key   = 'p',
		.arg   = "PORT",
		.flags = 0,
		.doc   = "Set the port to bind.",
		.group = 0
	},
	{
		.name  = "hostkey",
		.key   = 'k',
		.arg   = "FILE",
		.flags = 0,
		.doc   = "Set the host key.",
		.group = 0
	},
	{
		.name  = "dsakey",
		.key   = 'd',
		.arg   = "FILE",
		.flags = 0,
		.doc   = "Set the dsa key.",
		.group = 0
	},
	{
		.name  = "rsakey",
		.key   = 'r',
		.arg   = "FILE",
		.flags = 0,
		.doc   = "Set the rsa key.",
		.group = 0
	},
	{
		.name  = "verbose",
		.key   = 'v',
		.arg   = NULL,
		.flags = 0,
		.doc   = "Get verbose output.",
		.group = 0
	},
	{NULL, 0, NULL, 0, NULL, 0}
};

/* Parse a single option. */
static error_t parse_opt (int key, char *arg, struct argp_state *state) {
	/* Get the input argument from argp_parse, which we
	 * know is a pointer to our arguments structure.
	 */
	ssh_bind sshbind = state->input;

	switch (key) {
		case 'p':
			ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, arg);
			break;
		case 'd':
			ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, arg);
			break;
		case 'k':
			ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, arg);
			break;
		case 'r':
			ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, arg);
			break;
		case 'v':
			ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "3");
			break;
		case ARGP_KEY_ARG:
			if (state->arg_num >= 1) {
				/* Too many arguments. */
				argp_usage (state);
			}
			ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, arg);
			break;
		case ARGP_KEY_END:
			if (state->arg_num < 1) {
				/* Not enough arguments. */
				argp_usage (state);
			}
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

/* Our argp parser. */
static struct argp argp = {options, parse_opt, args_doc, doc, NULL, NULL, NULL};
#endif /* HAVE_ARGP_H */

int main(int argc, char **argv){
	ssh_session session;
	ssh_bind sshbind;
	struct ssh_server_callbacks_struct cb = {
		.userdata = NULL,
		.auth_password_function = auth_password,
		.auth_gssapi_mic_function = auth_gssapi_mic,
		.channel_open_request_session_function = new_session_channel,
		.service_request_function = service_request
	};
	struct ssh_callbacks_struct cb_gen = {
		.userdata = NULL,
		.global_request_function = global_request
	};

	int ret;

	sshbind = ssh_bind_new();
	session = ssh_new();
	mainloop = ssh_event_new();

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, KEYS_FOLDER "ssh_host_dsa_key");
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, KEYS_FOLDER "ssh_host_rsa_key");

#ifdef HAVE_ARGP_H
	/*
	 * Parse our arguments; every option seen by parse_opt will
	 * be reflected in arguments.
	 */
	argp_parse (&argp, argc, argv, 0, 0, sshbind);
#else
	(void) argc;
	(void) argv;
#endif

	if(ssh_bind_listen(sshbind)<0){
		printf("Error listening to socket: %s\n",ssh_get_error(sshbind));
		return 1;
	}

	if(ssh_bind_accept(sshbind,session) == SSH_ERROR){
		printf("error accepting a connection : %s\n",ssh_get_error(sshbind));
		ret = 1;
		goto shutdown;
	}

	ssh_callbacks_init(&cb);
	ssh_callbacks_init(&cb_gen);
	ssh_set_server_callbacks(session, &cb);
	ssh_set_callbacks(session, &cb_gen);
	ssh_set_message_callback(session, message_callback, (void *)NULL);

	if (ssh_handle_key_exchange(session)) {
		printf("ssh_handle_key_exchange: %s\n", ssh_get_error(session));
		ret = 1;
		goto shutdown;
	}
	ssh_set_auth_methods(session,SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_GSSAPI_MIC);
	ssh_event_add_session(mainloop, session);

	while (!authenticated){
		if(error)
			break;
		if (ssh_event_dopoll(mainloop, -1) == SSH_ERROR){
			printf("Error : %s\n", ssh_get_error(session));
			ret = 1;
			goto shutdown;
		}
	}
	if(error){
		printf("Error, exiting loop\n");
	} 
	else {
		printf("Authenticated and got a channel\n");
		
		while (!error){
			if (ssh_event_dopoll(mainloop, 100) == SSH_ERROR){
				printf("Error : %s\n", ssh_get_error(session));
				ret = 1;
				goto shutdown;
			}
		}
	}
	
shutdown:
	ssh_disconnect(session);
	ssh_bind_free(sshbind);
	ssh_finalize();
	return ret;
}

