/* Copyright (c) 2009 Sam Trenholme
 *
 * TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * This software is provided 'as is' with no guarantees of correctness or
 * fitness for purpose.
 */

/* Maximum number of open sockets; make this big like it is in *NIX */
#define FD_SETSIZE 512
#define sa_family_t uint16_t
#define socklen_t int32_t
#include <winsock.h>
#include <wininet.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

/* This is the header placed before the 4-byte IP; we change the last four
 * bytes to set the IP we give out in replies */
char p[17] = 
"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x7f\x7f\x7f\x7f";

/* microdns: This is a tiny DNS server that does only one thing: It
   always sends a given IPv4 IP to any and all queries sent to the server.

   The ip it sends is 10.11.12.13, and the service binds to the IP 127.0.0.1

   This program is a Windows service; I would like to thank Steve Friedl who
   put a public domain simple Windows service on his web site at unixwiz.net;
   his public domain code made it possible for me to write the Win32
   service code.

   To compile: 
	gcc -O3 -DMINGW -o microdns-service microdns-service.c -lwsock32

   After compiling, one needs to install this service:

	microdns-service.exe --install

   Then one can start the service:

	net start MicroDNS

   (It can also be started from Control Panel -> Administrative tools ->
    Services; look for the "MicroDNS server" service)

   To stop the service:

        net stop MicroDNS

   (Or from the Services control panel)

   To remove the service:

 	microdns-service.exe --remove

   This program has been verified to compile and run in a MinGW-3.1.0-1 +
   MSYS-1.0.10 environment; for details on how to set up this environment in
   Windows, go to this page:

   http://maradns.blogspot.com/2009/03/mingw-310-1-last-real-mingw-release.html

 */

void windows_socket_start() {
        WSADATA wsaData;
        WORD wVersionRequested = MAKEWORD(2,2);
        WSAStartup( wVersionRequested, &wsaData);
}

/* Based on command-line arguments, set the IP we will bind to and the
   IP we send over the pipe; note that we always use 10.11.12.13 because
   I don't think you can send command-line arguments to Win32 services */
uint32_t get_ip(int argc, char **argv) {

	uint32_t ip;

	/* Set the IP we give everyone */
	if(argc > 1) {
		ip = inet_addr(argv[1]);
	} else {
		ip = 0x0d0c0b0a; /* 10.11.12.13 */
	}
	ip = ntohl(ip);
	p[12] = (ip & 0xff000000) >> 24;
	p[13] = (ip & 0x00ff0000) >> 16;
	p[14] = (ip & 0x0000ff00) >>  8;
	p[15] = (ip & 0x000000ff);

	/* Set the IP we bind to (default is "0", which means "all IPs) */
	ip = 0;
	if(argc == 3) {
		ip = inet_addr(argv[2]);
	} 
	/* Return the IP we bind to */
	return ip;
}

/* Get port: Get a port locally and return the socket the port is on */
SOCKET get_port(uint32_t ip, char **argv, struct sockaddr_in *dns_udp) {
	SOCKET sock;
	int len_inet;

	/* Bind to port 53 */
	sock = socket(AF_INET,SOCK_DGRAM,0);
	if(sock == INVALID_SOCKET) {
		perror("socket error");
		exit(0);
	}
	memset(dns_udp,0,sizeof(struct sockaddr_in));
	dns_udp->sin_family = AF_INET;
	dns_udp->sin_port = htons(53);
	dns_udp->sin_addr.s_addr = ip;
	if(dns_udp->sin_addr.s_addr == INADDR_NONE) {
		printf("Problem with bind IP %s\n",argv[2]);
		exit(0);
	}
	len_inet = sizeof(struct sockaddr_in);
	if(bind(sock,(struct sockaddr *)dns_udp,len_inet) == -1) {
		printf("bind error");
		exit(0);
	}

	/* Linux kernel bug */
	/* fcntl(sock, F_SETFL, O_NONBLOCK); */

	return sock;
}	

int run_loop = 1;

/* The main loop for the program; this receives DNS queries and 
   makes replies */
void bigloop(SOCKET sock, struct sockaddr_in *dns_udp) {
	int a, len_inet;
	char in[512];
	socklen_t foo = sizeof(in);
	int leni = sizeof(struct sockaddr);
	struct timeval timeout;
	fd_set rx_set; /* Using select() because if its timeout option */

	/* Now that we know the IP and are on port 53, process incoming
         * DNS requests */
	while(run_loop == 1) {

		/* One second timeout (so we can stop the service) */
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		FD_ZERO(&rx_set);
		FD_SET(sock,&rx_set);
		a = select(sock + 1,&rx_set,NULL,NULL,&timeout);

		if(a > 0) { /* If we got data */
			/* Get data from UDP port 53 */
			len_inet = recvfrom(sock,in,255,0,
				(struct sockaddr *)&dns_udp,&foo);
		} else {
			continue;
		}
		/* Roy Arends check: We only answer questions */
		if(len_inet < 3 || (in[2] & 0x80) != 0x00) {
			continue;
		}

		/* Prepare the reply */
		if(len_inet > 12) {
			/* Make this an answer */
			in[2] |= 0x80;
			/* We add an additional answer */
			in[7]++;
		}
		for(a=0;a<16;a++) {
			in[len_inet + a] = p[a];
		}		

		/* Send the reply */
		sendto(sock,in,len_inet + 16,0, (struct sockaddr *)&dns_udp,
			leni);
	}
}

static SERVICE_STATUS           sStatus;
static SERVICE_STATUS_HANDLE    hServiceStatus = 0;
#define COUNTOF(x)       (sizeof(x) / sizeof((x)[0]) )

void md_install_service() {
	char szPath[512];

	GetModuleFileName( NULL, szPath, COUNTOF(szPath) );
	
	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, 
				SC_MANAGER_CREATE_SERVICE);

        SC_HANDLE hService = CreateService(
                        hSCManager,
                        "MicroDNS",                   /* name of service */
                        "MicroDNS server",            /* name to display */
                        SERVICE_ALL_ACCESS,           /* desired access */
                        SERVICE_WIN32_OWN_PROCESS,    /* service type */
                        SERVICE_AUTO_START,           /* start type */
                        SERVICE_ERROR_NORMAL,         /* error control type */
                        szPath,                       /* service's binary */
                        NULL,                         /* no load order grp */
                        NULL,                         /* no tag identifier */
                        "",                           /* dependencies */
                        0,                     /* LocalSystem account */
                        0);                    /* no password */

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);


}	
	
void md_service_control(DWORD dwControl) {
	switch (dwControl) {
		case SERVICE_CONTROL_SHUTDOWN:
		case SERVICE_CONTROL_STOP:

		sStatus.dwCurrentState  = SERVICE_STOP_PENDING;
		sStatus.dwCheckPoint    = 0;
		sStatus.dwWaitHint      = 2000; /* Two seconds */
		sStatus.dwWin32ExitCode = 0;
		run_loop = 0;
		
		default:
			sStatus.dwCheckPoint = 0;
	}
	SetServiceStatus(hServiceStatus, &sStatus);
}

void md_service_main(int argc, char **argv) {
	SOCKET sock;
	struct sockaddr_in dns_udp;
	uint32_t ip = 0; /* 0.0.0.0; default bind IP */

	hServiceStatus = RegisterServiceCtrlHandler(argv[0],
		(void *)md_service_control);
	if(hServiceStatus == 0) {
		return;
	}

	sStatus.dwServiceType                   = SERVICE_WIN32_OWN_PROCESS;
        sStatus.dwCurrentState                  = SERVICE_START_PENDING;
        sStatus.dwControlsAccepted              = SERVICE_ACCEPT_STOP
                                                | SERVICE_ACCEPT_SHUTDOWN;
        sStatus.dwWin32ExitCode                 = 0;
        sStatus.dwServiceSpecificExitCode       = 0;
        sStatus.dwCheckPoint                    = 0;
        sStatus.dwWaitHint                      = 2 * 1000; /* Two seconds */
	sStatus.dwCurrentState = SERVICE_RUNNING;

	SetServiceStatus(hServiceStatus, &sStatus);

	/* The actual code the service runs */
	windows_socket_start();
	ip = get_ip(argc, argv);
	sock = get_port(ip,argv,&dns_udp);
	bigloop(sock,&dns_udp);

	/* Clean up the stopped service; otherwise we get a nasty error in
	   Win32 */
	sStatus.dwCurrentState  = SERVICE_STOPPED;
	SetServiceStatus(hServiceStatus, &sStatus);
	
}

void md_remove_service() {
	char szPath[512];
	SC_HANDLE hService = 0;
	SC_HANDLE hSCManager = OpenSCManager(0,0,0);
	hService = OpenService	(hSCManager,"MicroDNS",DELETE);
	DeleteService(hService);
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);

}	

int main(int argc, char **argv) {

	int a=0;
	char *b;
	int action = 0;

	static SERVICE_TABLE_ENTRY      Services[] = {
		{ "MicroDNS",  (void *)md_service_main },
		{ 0 }
	};
	if(argc > 1) {
		b = argv[1];
		for(a=0;a<10 && *b;a++) {
			if(*b == 'r') {
				action = 1;
			}
			b++;
		}
		if(action == 1) {
			md_remove_service();
		} else {		
			md_install_service();
		}
		return 0;
	}
	if (!StartServiceCtrlDispatcher(Services)) {
		printf("Fatal: Can not start service!\n");
		return 1;
	}
	return 0;

}
