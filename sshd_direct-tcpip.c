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

struct event_fd_data_struct {
	int *p_fd;
	ssh_channel channel;
	int stacked;
};

struct cleanup_node_struct {
	struct event_fd_data_struct *data;
	struct cleanup_node_struct *next;
};

static struct cleanup_node_struct *cleanup_stack;

static void _close_socket( struct event_fd_data_struct event_fd_data);

void cleanup_push(struct cleanup_node_struct** head_ref, struct event_fd_data_struct *new_data) { 
	// Allocate memory for node 
	struct cleanup_node_struct *new_node = (struct cleanup_node_struct*)malloc(sizeof(struct cleanup_node_struct)); 
  
	new_node->next = (*head_ref); 
  
	// Copy new_data  
	new_node->data = new_data;
  
	// Change head pointer as new node is added at the beginning 
	(*head_ref)    = new_node; 
}

void do_cleanup(struct cleanup_node_struct **head_ref) {
	struct cleanup_node_struct *current = (*head_ref);
	struct cleanup_node_struct *previous = NULL, *gone = NULL;
	
	while (current != NULL) {
		if(ssh_channel_is_closed(current->data->channel)) {
			gone = current;
			current = gone->next;
			if (gone == (*head_ref)) {
				(*head_ref) = current;
			}
			if (previous != NULL) {
				previous->next = current;
			}
			previous = current;
			_close_socket(*gone->data);
			ssh_channel_free(gone->data->channel);
			//free(gone->data->p_fd);
			//free(gone->data);
			SAFE_FREE(gone);
			_ssh_log(SSH_LOG_FUNCTIONS, "=== do_cleanup", "Freed.");
		}
		else {
			ssh_channel_close(current->data->channel);
			previous = current;
			current = current->next;
		}
	}
}

static int auth_password(ssh_session session, const char *user,
		const char *password, void *userdata){
	(void)userdata;
	_ssh_log(SSH_LOG_PROTOCOL, "=== auth_password", "Authenticating user %s pwd %s",user, password);
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
	_ssh_log(SSH_LOG_PROTOCOL, "=== subsystem_request", "Channel subsystem reqeuest: %s", subsystem);
	return 0;
}

struct ssh_channel_callbacks_struct channel_cb = {
	.channel_subsystem_request_function = subsystem_request
}; 

static ssh_channel new_session_channel(ssh_session session, void *userdata){
	(void) session;
	(void) userdata;
	_ssh_log(SSH_LOG_PROTOCOL, "=== subsystem_request", "Session channel request");
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

static void stack_socket_close(ssh_session session, struct event_fd_data_struct *event_fd_data) {
	if (event_fd_data->stacked != 1) {
		sockets_cnt--;
		_ssh_log(SSH_LOG_FUNCTIONS, "=== stack_socket_close", "Closing fd = %d sockets_cnt = %d", *event_fd_data->p_fd, sockets_cnt);
		event_fd_data->stacked = 1;
		cleanup_push(&cleanup_stack, event_fd_data);
	}
}

static void _close_socket( struct event_fd_data_struct event_fd_data) {
	_ssh_log(SSH_LOG_FUNCTIONS, "=== close_socket", "Closing fd = %d sockets_cnt = %d", *event_fd_data.p_fd, sockets_cnt);
	ssh_session session = ssh_channel_get_session(event_fd_data.channel);
	//ssh_event_remove_session(mainloop, session);
	ssh_event_remove_fd(mainloop, *event_fd_data.p_fd);
	//ssh_event_add_session(mainloop, session);
	close(*event_fd_data.p_fd);
}

static int service_request(ssh_session session, const char *service, void *userdata){
	(void)session;
	//(void)service;
	(void)userdata;
	_ssh_log(SSH_LOG_PROTOCOL, "=== service_request", "Service request: %s", service);
	return 0;
}

static void global_request(ssh_session session, ssh_message message, void *userdata){
	(void)session;
	(void)userdata;
	_ssh_log(SSH_LOG_PROTOCOL, "=== global_request", "Global request, message type: %d", ssh_message_type(message));
}

static void my_channel_close_function(ssh_session session, ssh_channel channel, void *userdata) {
	(void)session;

	struct event_fd_data_struct *event_fd_data = (struct event_fd_data_struct *)userdata;
	_ssh_log(SSH_LOG_PROTOCOL, "=== my_channel_close_function", "Channel %d:%d closed by remote. State=%d", channel->local_channel, channel->remote_channel, channel->state);
	
	stack_socket_close(session, event_fd_data);
}

static void my_channel_eof_function(ssh_session session, ssh_channel channel, void *userdata) {
	(void)session;
	//(void)userdata;
	struct event_fd_data_struct *event_fd_data = (struct event_fd_data_struct *)userdata;
	_ssh_log(SSH_LOG_PROTOCOL, "=== my_channel_eof_function", "Got EOF on channel %d:%d. Shuting down write on socket (fd = %d).", channel->local_channel, channel->remote_channel, *event_fd_data->p_fd);

	stack_socket_close(session, event_fd_data);
}

static void my_channel_exit_status_function(ssh_session session, ssh_channel channel, int exit_status, void *userdata) {
	(void)session;
	//(void)userdata;
	struct event_fd_data_struct *event_fd_data = (struct event_fd_data_struct *)userdata;
	_ssh_log(SSH_LOG_PROTOCOL, "=== my_channel_exit_status_function", "Got exit status %d on channel %d:%d fd = %d.", exit_status, channel->local_channel, channel->remote_channel, *event_fd_data->p_fd);
}

static int my_channel_data_function(ssh_session session, ssh_channel channel, void *data, uint32_t len, int is_stderr, void *userdata) {
	int i = 0;
	struct event_fd_data_struct *event_fd_data = (struct event_fd_data_struct *)userdata;

	_ssh_log(SSH_LOG_PROTOCOL, "=== my_channel_data_function", "%d bytes waiting on channel %d:%d for reading. Fd = %d",len, channel->local_channel, channel->remote_channel, *event_fd_data->p_fd);
	if (len > 0) {
		i = send(*event_fd_data->p_fd, data, len, 0);
	}
	if (i < 0) {
		_ssh_log(SSH_LOG_WARNING, "=== my_channel_data_function", "Writing to tcp socket %s", strerror(errno));
		stack_socket_close(session, event_fd_data);
		ssh_channel_send_eof(channel);
	}
	else {
		_ssh_log(SSH_LOG_FUNCTIONS, "=== my_channel_data_function", "Sent %d bytes", i);
	}
	return i;
}

static int cb_readsock(socket_t fd, int revents, void *userdata) {
	struct event_fd_data_struct *event_fd_data = (struct event_fd_data_struct *)userdata;
	ssh_channel channel = event_fd_data->channel;
	ssh_session session;
	int len, i, wr;
	char buf[16384];
	int	blocking;

	if(channel == NULL) {
		_ssh_log(SSH_LOG_FUNCTIONS, "=== cb_readsock", "channel == NULL!");
		return 0;
	}

	session = ssh_channel_get_session(channel);

	if(ssh_channel_is_closed(channel)) {
		_ssh_log(SSH_LOG_FUNCTIONS, "=== cb_readsock", "channel is closed!");
		stack_socket_close(session, event_fd_data);
		//shutdown(fd, SHUT_WR);
		return 0;
	}

	if(!(revents & POLLIN)) {
        if (revents & POLLPRI) {
            _ssh_log(SSH_LOG_PROTOCOL, "=== cb_readsock", "poll revents & POLLPRI" );
        }
        if (revents & POLLOUT) {
            _ssh_log(SSH_LOG_PROTOCOL, "=== cb_readsock", "poll revents & POLLOUT" );
        }
        if (revents & POLLHUP) {
            _ssh_log(SSH_LOG_PROTOCOL, "=== cb_readsock", "poll revents & POLLHUP" );
        }
        if (revents & POLLNVAL) {
            _ssh_log(SSH_LOG_PROTOCOL, "=== cb_readsock", "poll revents & POLLNVAL");
        }
        if (revents & POLLERR) {
            _ssh_log(SSH_LOG_PROTOCOL, "=== cb_readsock", "poll revents & POLLERR");
        }
        //if (revents & POLLRDHUP) {
        //    printf(" POLLRDHUP");
        //}
		return 0;
	}

	blocking = ssh_is_blocking(session);
	ssh_set_blocking(session, 0);

	_ssh_log(SSH_LOG_FUNCTIONS, "=== cb_readsock", "Trying to read from tcp socket fd = %d... (Channel %d:%d state=%d)", 
						*event_fd_data->p_fd, channel->local_channel, channel->remote_channel, channel->state);
	len = recv(*event_fd_data->p_fd, buf, sizeof(buf), 0);
	if (len < 0) {
		_ssh_log(SSH_LOG_WARNING, "=== cb_readsock", "Reading from tcp socket: %s", strerror(errno));
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
					_ssh_log(SSH_LOG_WARNING, "=== cb_readsock", "Error writing on the direct-tcpip channel: %d", i);
					len = wr;
					break;
				}
				wr += i;
				_ssh_log(SSH_LOG_FUNCTIONS, "=== cb_readsock", "channel_write (%d from %d)", wr, len);
			} while (i > 0 && wr < len);
		}
		else {
			_ssh_log(SSH_LOG_WARNING, "=== cb_readsock", "Can't write on closed channel!");
		}
	}
	else {
		_ssh_log(SSH_LOG_PROTOCOL, "=== cb_readsock", "The destination host has disconnected!");

		ssh_channel_close(channel);
		shutdown(*event_fd_data->p_fd, SHUT_RD);

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
		_ssh_log(SSH_LOG_WARNING, "=== open_tcp_socket", "ERROR opening socket: %s", strerror(errno));
		return -1;
	}
	
	dest_hostname = ssh_message_channel_request_open_destination(msg);
	dest_port = ssh_message_channel_request_open_destination_port(msg);
	
	_ssh_log(SSH_LOG_PROTOCOL, "=== open_tcp_socket", "Connecting to %s on port %d", dest_hostname, dest_port);

	host = gethostbyname(dest_hostname);
	if (host == NULL) {
		_ssh_log(SSH_LOG_WARNING, "=== open_tcp_socket", "ERROR, no such host: %s", dest_hostname);
		return -1;
	}

	bzero((char *) &sin, sizeof(sin));
	sin.sin_family = AF_INET;
	bcopy((char *)host->h_addr, (char *)&sin.sin_addr.s_addr, host->h_length);
	sin.sin_port = htons(dest_port);

	if (connect(forwardsock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		_ssh_log(SSH_LOG_WARNING, "=== open_tcp_socket", "ERROR connecting: %s", strerror(errno));
		return -1;
	}

	sockets_cnt++;
	_ssh_log(SSH_LOG_FUNCTIONS, "=== open_tcp_socket", "Connected. sockets_cnt = %d", sockets_cnt);
	return forwardsock;
}


static int message_callback(ssh_session session, ssh_message message, void *userdata){
	(void)session;
	(void)message;
	(void)userdata;
	ssh_channel channel;
	int *pFd;
	struct ssh_channel_callbacks_struct *cb_chan;
	struct event_fd_data_struct  *event_fd_data;

	//int dest_port;
	_ssh_log(SSH_LOG_PACKET, "=== message_callback", "Message type: %d", ssh_message_type(message));
	_ssh_log(SSH_LOG_PACKET, "=== message_callback", "Message Subtype: %d", ssh_message_subtype(message));
	if(ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN) {
		//printf("channel_request_open.sender: %d\n", message->channel_request_open.sender);
		_ssh_log(SSH_LOG_PROTOCOL, "=== message_callback", "channel_request_open");
		
		if (ssh_message_subtype(message) == SSH_CHANNEL_DIRECT_TCPIP) {
			channel = ssh_message_channel_request_open_reply_accept(message);

			//	return 0;
			if (channel == NULL) {
				_ssh_log(SSH_LOG_WARNING, "=== message_callback", "Accepting direct-tcpip channel failed!");
				return 1;
			}
			else {
				_ssh_log(SSH_LOG_PROTOCOL, "=== message_callback", "Connected to channel!");
				pFd = malloc(sizeof(int));
				cb_chan = malloc(sizeof(struct ssh_channel_callbacks_struct));
				event_fd_data = malloc(sizeof(struct event_fd_data_struct));
				
				*pFd = open_tcp_socket(message);
				if (-1 == *pFd) {
					return 1;
				}

				event_fd_data->channel = channel;
				event_fd_data->p_fd = pFd;
				event_fd_data->stacked = 0;

				cb_chan->userdata = event_fd_data;
				cb_chan->channel_eof_function = my_channel_eof_function;
				cb_chan->channel_close_function = my_channel_close_function;
				cb_chan->channel_data_function = my_channel_data_function;
				cb_chan->channel_exit_status_function = my_channel_exit_status_function;

				ssh_callbacks_init(cb_chan);
				ssh_set_channel_callbacks(channel, cb_chan);
				
				ssh_event_add_fd(mainloop, (socket_t)*pFd, POLLIN, cb_readsock, event_fd_data);

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
			ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "4");
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
			do_cleanup(&cleanup_stack);
		}
	}
	
shutdown:
	ssh_disconnect(session);
	ssh_bind_free(sshbind);
	ssh_finalize();
	return ret;
}

