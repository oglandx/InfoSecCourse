#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>

#include <string.h>

#define BUFFER_SIZE 255

int main() {
	char buffer[BUFFER_SIZE];
	char *rec_srt="Greeting (SomeServer 2.4)\n";

	int listen_fd, comm_fd;
	struct sockaddr_in servaddr;

	listen_fd = socket(AF_INET, SOCK_STREAM, 0);

	bzero(&servaddr, sizeof(servaddr));

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htons(INADDR_ANY);
	servaddr.sin_port = htons(10000);

	bind(listen_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));

	listen(listen_fd, 10);

	comm_fd = accept(listen_fd, (struct sockaddr*) NULL, NULL);

	while(1) {
		bzero(buffer, BUFFER_SIZE);
		read(comm_fd,buffer, BUFFER_SIZE);
		printf("You wrote: %s", buffer);
		write(comm_fd, rec_srt, strlen(rec_srt)+1);
	}
}