
/**
 * @file telemetry_client.c
 * @brief DPDK Telemetry V2 Client Implementation in C (No external dependencies)
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <pwd.h>
#include <limits.h>
#include <ctype.h>
#include <termios.h>
#include <sys/ioctl.h>

#define TELEMETRY_VERSION "v2"
#define SOCKET_NAME "dpdk_telemetry." TELEMETRY_VERSION
#define DEFAULT_PREFIX "rte"
#define MAX_BUF_LEN 4096
#define MAX_PATH_LEN 1024
#define MAX_CMDS 100
#define MAX_HISTORY 100

typedef struct {
	char *file_prefix;
	int instance;
	int list_mode;
} cmdline_args_t;

char *g_commands[MAX_CMDS];
size_t g_command_count = 0;
char *g_history[MAX_HISTORY];
int g_history_count = 0;
int g_history_index = -1;

char cmdline_cmd[MAX_BUF_LEN] = {0};

/**
 * @brief Terminal control functions
 */
void set_terminal_raw_mode()
{
	struct termios term;
	tcgetattr(STDIN_FILENO, &term);
	term.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

void restore_terminal_mode()
{
	struct termios term;
	tcgetattr(STDIN_FILENO, &term);
	term.c_lflag |= (ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

/**
 * @brief Clear current line from cursor to end
 */
void clear_line_from_cursor()
{
	printf("\033[K"); // Clear from cursor to end of line
}

/**
 * @brief Move cursor to beginning of line
 */
void move_cursor_to_start()
{
	printf("\r"); // Move to start of line
}

/**
 * @brief Get terminal width
 */
int get_terminal_width()
{
#ifdef TIOCGWINSZ
	struct winsize ws;
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
		return ws.ws_col;
	}
#endif
	return 80; // Default width
}

static int split_string(const char *str, char *argv[50], const char*new_spliter)
{
	int cnts = 0;
	char *token;
	const char* spliter=" ,\t\n";
	static char buf[MAX_BUF_LEN+10];

	if(str == NULL){
		return 0;
	}
	if(new_spliter)
		spliter = new_spliter;

	strcpy(buf, str);
	token = strtok(buf, spliter); 

	while (token != NULL && (cnts < 50)) {
		argv[cnts++] = token;
		token = strtok(NULL, spliter);
	}
	return cnts;
}

/**
 * @brief Simple JSON parsing functions
 */
char *json_find_value(const char *json_str, const char *key)
{
	char pattern[128];
	snprintf(pattern, sizeof(pattern), "\"%s\":", key);

	char *pos = strstr(json_str, pattern);
	if (!pos) return NULL;

	pos += strlen(pattern);
	while (*pos && isspace(*pos)) pos++;

	if (*pos == '"') {
		// String value
		pos++;
		char *end = strchr(pos, '"');
		if (!end) return NULL;

		size_t len = end - pos;
		char *value = malloc(len + 1);
		strncpy(value, pos, len);
		value[len] = '\0';
		return value;
	} else if (isdigit(*pos)) {
		// Numeric value
		char *end = pos;
		while (*end && (isdigit(*end) || *end == '.')) end++;

		size_t len = end - pos;
		char *value = malloc(len + 1);
		strncpy(value, pos, len);
		value[len] = '\0';
		return value;
	}

	return NULL;
}

/**
 * @brief Parse JSON array of commands
 */
int parse_commands_array(const char *json_str, const char *key, char ***commands, size_t *count)
{
	char pattern[128];
	snprintf(pattern, sizeof(pattern), "\"%s\":", key);

	char *pos = strstr(json_str, pattern);
	if (!pos) return -1;

	pos += strlen(pattern);
	while (*pos && isspace(*pos)) pos++;

	if (*pos != '[') return -1;
	pos++;

	*count = 0;
	*commands = malloc(MAX_CMDS * sizeof(char *));

	while (*pos && *pos != ']') {
		while (*pos && isspace(*pos)) pos++;

		if (*pos == '"') {
			pos++;
			char *end = strchr(pos, '"');
			if (!end) break;

			size_t len = end - pos;
			(*commands)[*count] = malloc(len + 1);
			strncpy((*commands)[*count], pos, len);
			(*commands)[*count][len] = '\0';
			(*count)++;

			pos = end + 1;
			while (*pos && (*pos == ',' || isspace(*pos))) pos++;
		} else {
			break;
		}
	}

	return 0;
}

/**
 * @brief Pretty print JSON string
 */
void pretty_print_json(const char *json_str)
{
	int indent = 0;
	int in_string = 0;

	for (const char *p = json_str; *p; p++) {
		if (*p == '\\') {
			if( *(p+1) == 'n'){
				putchar('\n');
				p++;
				continue;
			}else if( *(p+1) == 't'){
				putchar('\t');
				p++;
				continue;
			}
		}
		if (*p == '"' && (p == json_str || *(p-1) != '\\')) {
			in_string = !in_string;
			putchar(*p);
		} else if (!in_string) {
			switch (*p) {
				case '{':
				case '[':
					putchar(*p);
					putchar('\n');
					indent++;
					for (int i = 0; i < indent; i++) printf("  ");
					break;
				case '}':
				case ']':
					putchar('\n');
					indent--;
					for (int i = 0; i < indent; i++) printf("  ");
					putchar(*p);
					break;
				case ',':
					putchar(*p);
					putchar('\n');
					for (int i = 0; i < indent; i++) printf("  ");
					break;
				case ':':
					putchar(*p);
					putchar(' ');
					break;
				default:
					putchar(*p);
			}
		} else {
			putchar(*p);
		}
	}
	putchar('\n');
}

/**
 * @brief Get DPDK runtime directory using same logic as DPDK EAL
 */
char *get_dpdk_runtime_dir(const char *file_prefix)
{
	static char path[MAX_PATH_LEN];
	const char *run_dir = getenv("RUNTIME_DIRECTORY");

	if (!run_dir) {
		if (geteuid() == 0) {
			run_dir = "/var/run";
		} else {
			run_dir = getenv("XDG_RUNTIME_DIR");
			if (!run_dir) {
				run_dir = "/tmp";
			}
		}
	}

	snprintf(path, sizeof(path), "%s/dpdk/%s", run_dir, file_prefix);
	return path;
}

/**
 * @brief Read data from socket
 */
int read_socket(int sock, char *buffer, size_t buf_len, int echo, int pretty)
{
	size_t bytes_read = recv(sock, buffer, buf_len - 1, 0);
	if (bytes_read <= 0) {
		perror("recv failed");
		return -1;
	}
	buffer[bytes_read] = '\0';

	if (echo) {
		if (pretty) {
			pretty_print_json(buffer);
		} else {
			printf("%s\n", buffer);
		}
	}

	return 0;
}

/**
 * @brief Get application name from PID
 */
char *get_app_name(pid_t pid)
{
	char path[MAX_PATH_LEN];
	char cmdline[MAX_BUF_LEN];
	char *app_name = NULL;
	int fd;

	snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		return NULL;
	}

	ssize_t bytes_read = read(fd, cmdline, sizeof(cmdline) - 1);
	close(fd);

	if (bytes_read > 0) {
		cmdline[bytes_read] = '\0';
		char *basename = strrchr(cmdline, '/');
		app_name = strdup(basename ? basename + 1 : cmdline);
	}

	return app_name;
}

/**
 * @brief Find all telemetry sockets in given directory
 */
void find_sockets(const char *path, char ***sockets, int *count)
{
	DIR *dir;
	struct dirent *entry;

	*sockets = NULL;
	*count = 0;

	dir = opendir(path);
	if (!dir) {
		return;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (strstr(entry->d_name, SOCKET_NAME) == entry->d_name) {
			*sockets = realloc(*sockets, (*count + 1) * sizeof(char *));
			(*sockets)[*count] = malloc(strlen(path) + strlen(entry->d_name) + 2);
			sprintf((*sockets)[*count], "%s/%s", path, entry->d_name);
			(*count)++;
		}
	}
	closedir(dir);
}

/**
 * @brief Print socket connection options
 */
void print_socket_options(const char *prefix, char **sockets, int count)
{
	char cmd[256];
	snprintf(cmd, sizeof(cmd), "./telemetry_client -f %s", prefix);

	for (int i = 0; i < count; i++) {
		char *basename = strrchr(sockets[i], '/');
		if (basename) basename++;

		if (strstr(basename, SOCKET_NAME) == basename) {
			printf("- %s  # Connect with '%s'\n", basename, cmd);
		} else {
			char *instance_str = strchr(basename, ':');
			if (instance_str) {
				printf("- %s  # Connect with '%s -i %s'\n",
						basename, cmd, instance_str + 1);
			}
		}
	}
}

/**
 * @brief List all available file prefixes
 */
void list_file_prefixes()
{
	char runtime_dir[MAX_PATH_LEN];
	char path[2048];
	DIR *dir;
	struct dirent *entry;

	snprintf(runtime_dir, sizeof(runtime_dir), "%s/dpdk",
			geteuid() == 0 ? "/var/run" :
			getenv("XDG_RUNTIME_DIR") ? getenv("XDG_RUNTIME_DIR") : "/tmp");

	dir = opendir(runtime_dir);
	if (!dir) {
		printf("No DPDK apps with telemetry enabled available\n");
		return;
	}

	printf("Valid file-prefixes:\n\n");

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.') {
			continue;
		}

		snprintf(path, sizeof(path), "%s/%s", runtime_dir, entry->d_name);
		struct stat st;
		if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
			char **sockets = NULL;
			int socket_count = 0;

			find_sockets(path, &sockets, &socket_count);
			if (socket_count > 0) {
				printf("%s\n", entry->d_name);
				print_socket_options(entry->d_name, sockets, socket_count);
				printf("\n");
			}

			for (int i = 0; i < socket_count; i++) {
				free(sockets[i]);
			}
			free(sockets);
		}
	}
	closedir(dir);
}

/**
 * @brief Add command to history
 */
void add_to_history(const char *command)
{
	if (g_history_count >= MAX_HISTORY) {
		free(g_history[0]);
		memmove(g_history, g_history + 1, (MAX_HISTORY - 1) * sizeof(char *));
		g_history_count--;
	}

	g_history[g_history_count++] = strdup(command);
	g_history_index = g_history_count;
}

/**
 * @brief Get previous history command
 */
const char *get_prev_history()
{
	if (g_history_count == 0) return NULL;

	if (g_history_index > 0) {
		g_history_index--;
	}
	return g_history[g_history_index];
}

/**
 * @brief Get next history command
 */
const char *get_next_history()
{
	if (g_history_count == 0) return NULL;

	if (g_history_index < g_history_count - 1) {
		g_history_index++;
		return g_history[g_history_index];
	} else {
		g_history_index = g_history_count;
		return ""; // Return empty string for new input
	}
}

/**
 * @brief Find command completion matches
 */
void find_completion_matches(const char *text, char **matches, int *match_count)
{
	*match_count = 0;

	// Check "quit" command
	if (strncmp("quit", text, strlen(text)) == 0) {
		matches[(*match_count)++] = "quit";
	}

	// Check telemetry commands
	for (size_t i = 0; i < g_command_count; i++) {
		if (strncmp(g_commands[i], text, strlen(text)) == 0) {
			matches[(*match_count)++] = g_commands[i];
		}
	}
}

/**
 * @brief Find longest common prefix of matches
 */
char *find_common_prefix(char **matches, int match_count)
{
	if (match_count == 0) return strdup("");
	if (match_count == 1) return strdup(matches[0]);

	// Find the shortest string
	int min_len = strlen(matches[0]);
	for (int i = 1; i < match_count; i++) {
		int len = strlen(matches[i]);
		if (len < min_len) min_len = len;
	}

	// Find common prefix
	int prefix_len = 0;
	for (int i = 0; i < min_len; i++) {
		char c = matches[0][i];
		int same = 1;

		for (int j = 1; j < match_count; j++) {
			if (matches[j][i] != c) {
				same = 0;
				break;
			}
		}

		if (same) {
			prefix_len++;
		} else {
			break;
		}
	}

	char *prefix = malloc(prefix_len + 1);
	strncpy(prefix, matches[0], prefix_len);
	prefix[prefix_len] = '\0';

	return prefix;
}

/**
 * @brief Display completion matches in columns
 */
void display_completion_matches(char **matches, int match_count)
{
	int terminal_width = get_terminal_width();
	int max_len = 0;

	// Find maximum match length
	for (int i = 0; i < match_count; i++) {
		int len = strlen(matches[i]);
		if (len > max_len) max_len = len;
	}

	int col_width = max_len + 2; // Add some spacing
	int cols = terminal_width / col_width;
	if (cols < 1) cols = 1;

	printf("\n");
	for (int i = 0; i < match_count; i++) {
		printf("%-*s", col_width, matches[i]);
		if ((i + 1) % cols == 0) {
			printf("\n");
		}
	}

	// If last line wasn't complete, add a newline
	if (match_count % cols != 0) {
		printf("\n");
	}
}

/**
 * @brief Advanced line input with full editing support
 */
char *advanced_readline(const char *prompt)
{
	static char buffer[MAX_BUF_LEN];
	size_t pos = 0;
	int c;
	int escape_seq = 0;
	int escape_seq_step = 0;

	printf("%s", prompt);
	fflush(stdout);

	set_terminal_raw_mode();

	memset(buffer, 0, sizeof(buffer));

	while (1) {
		c = getchar();

		if (escape_seq) {
			if (escape_seq_step == 0) {
				// First character after ESC - should be '['
				if (c == '[') {
					escape_seq_step = 1;
				} else {
					// Not a valid escape sequence, reset
					escape_seq = 0;
					escape_seq_step = 0;
				}
				continue;
			} else if (escape_seq_step == 1) {
				// Second character after ESC - this is the actual command
				switch (c) {
					case 'A': // Up arrow - history previous
						{
							const char *prev = get_prev_history();
							if (prev) {
								// Clear current line
								move_cursor_to_start();
								clear_line_from_cursor();
								strncpy(buffer, prev, sizeof(buffer) - 1);
								buffer[sizeof(buffer) - 1] = '\0';
								pos = strlen(buffer);
								printf("%s%s", prompt, buffer);
							}
						}
						break;
					case 'B': // Down arrow - history next
						{
							const char *next = get_next_history();
							if (next) {
								move_cursor_to_start();
								clear_line_from_cursor();
								strncpy(buffer, next, sizeof(buffer) - 1);
								buffer[sizeof(buffer) - 1] = '\0';
								pos = strlen(buffer);
								printf("%s%s", prompt, buffer);
							}
						}
						break;
					case 'C': // Right arrow
						if (pos < strlen(buffer)) {
							putchar(buffer[pos]);
							pos++;
						}
						break;
					case 'D': // Left arrow
						if (pos > 0) {
							printf("\b");
							pos--;
						}
						break;
				}
				// Reset escape sequence state
				escape_seq = 0;
				escape_seq_step = 0;
			}
			continue;
		}

		if (c == 27) { // ESC character - start of escape sequence
			escape_seq = 1;
			escape_seq_step = 0;
			continue;
		}

		if (c == EOF || c == '\n' || c == '\r') {
			break;
		} else if (c == 127 || c == 8) { // Backspace
			if (pos > 0) {
				pos--;
				buffer[pos] = '\0';
				printf("\b \b");
				fflush(stdout);
			}
		} else if (c == '\t') { // Tab completion
			char *matches[MAX_CMDS + 1];
			int match_count = 0;

			find_completion_matches(buffer, matches, &match_count);

			if (match_count == 0) {
				// No matches, do nothing
			} else if (match_count == 1) {
				// Single match - complete it
				move_cursor_to_start();
				clear_line_from_cursor();
				strcpy(buffer, matches[0]);
				pos = strlen(buffer);
				printf("%s%s", prompt, buffer);
			} else {
				// Multiple matches - find common prefix
				char *common_prefix = find_common_prefix(matches, match_count);

				if (strlen(common_prefix) > strlen(buffer)) {
					// Common prefix is longer than current input - complete to common prefix
					move_cursor_to_start();
					clear_line_from_cursor();
					strcpy(buffer, common_prefix);
					pos = strlen(buffer);
					printf("%s%s", prompt, buffer);
				} else {
					// Show all matches
					move_cursor_to_start();
					clear_line_from_cursor();
					display_completion_matches(matches, match_count);
					printf("%s%s", prompt, buffer);
				}

				free(common_prefix);
			}
		} else if (c == 3) { // Ctrl-C
			restore_terminal_mode();
			printf("^C\n");
			return NULL;
		} else if (pos < sizeof(buffer) - 1) {
			buffer[pos++] = c;
			putchar(c);
			fflush(stdout);
		}
	}

	buffer[pos] = '\0';
	printf("\n");

	restore_terminal_mode();

	return (pos > 0) ? strdup(buffer) : strdup("");
}

/**
 * @brief Cleanup commands array
 */
void cleanup_commands()
{
	for (size_t i = 0; i < g_command_count; i++) {
		free(g_commands[i]);
	}
	g_command_count = 0;
}

/**
 * @brief Cleanup history array
 */
void cleanup_history()
{
	for (int i = 0; i < g_history_count; i++) {
		free(g_history[i]);
	}
	g_history_count = 0;
	g_history_index = -1;
}

/*
	adj /mce/xx a0 a1 -> /mce/xx,a0 a1	
*/
void adj_input(char* input_msg)
{
	int argc,i,cnt=0;
	char* argv[50];

	argc = split_string(input_msg,argv," ");
	if(argc <=1){
		return;
	}
	if(strchr(argv[0],',')){
		return;
	}
	cnt += sprintf(input_msg,"%s,%s",argv[0],argv[1]);
	for(i=2;i<argc;i++){
		cnt += sprintf(input_msg + cnt," %s",argv[i]);
	}
}

void input_map(char* input_msg)
{
	int argc, i,cnt=0;
	char* argv[50];
	char* mapped_path = NULL;

	if(!input_msg || input_msg[0] == '/' || input_msg[0] == 0)
		return;

	argc = split_string(input_msg,argv," ");
	if(argc == 0)
		return;

	if(0 == strcmp(argv[0],"md") || 0 == strcmp(argv[0],"rd")){
		mapped_path  = "/mce/reg_read";
	}else if(0 == strcmp(argv[0],"mw")|| 0 == strcmp(argv[0],"wr")){
		mapped_path  = "/mce/reg_write";
	}else if(0 == strcmp(argv[0],"link")){
		int port_id = 0;
		if(argc >=2)
			port_id = atoi(argv[1]);
		sprintf(input_msg,"/mce/dump,%d link", port_id);
		return;
	}else if(0 == strcmp(argv[0],"version")){
		int port_id = 0;
		if(argc >=2)
			port_id = atoi(argv[1]);
		sprintf(input_msg,"/mce/dump,%d version", port_id);
		return;
	}else if(0 == strcmp(argv[0],"port")){
		int port_id = 0;
		if(argc >=2)
			port_id = atoi(argv[1]);
		sprintf(input_msg,"/mce/dump,%d port", port_id);
		return;
	}else if(0 == strcmp(argv[0],"sfp-info")){
		int port_id = 0;
		if(argc >=2)
			port_id = atoi(argv[1]);
		sprintf(input_msg,"/mce/dump,%d sfp-info", port_id);
		return;
	}else if(0 == strcmp(argv[0],"dump")){
		int port_id = 0;
		unsigned int dump_value= 0;
		if(argc != 3){
			printf("Usage: dump <port_id> <dump_value>\n");
			return;
		}
		port_id = atoi(argv[1]);
		dump_value = strtoul(argv[2], NULL, 0);
		sprintf(input_msg,"/mce/dump,%d 0x%x", port_id,dump_value);
		return;
	}else if(0 == strcmp(argv[0],"quit")||0 == strcmp(argv[0],"exit") ||0 == strcmp(argv[0],"q")){
		return;
	}else {
		cnt += sprintf(input_msg,"/mce/%s", argv[0]);
		for(i=1;i<argc;i++){
			cnt += sprintf(input_msg + cnt," %s",argv[i]);
		}
		return;
	}

	if(mapped_path){
		cnt += sprintf(input_msg,"%s", mapped_path);
		for(i=1;i<argc;i++){
			cnt += sprintf(input_msg + cnt," %s",argv[i]);
		}
	}
}


#define __unused __attribute__((__unused__))
/**
 * @brief Handle socket connection and user interaction
 */
void handle_socket(const cmdline_args_t *args __unused,
		  const char *sock_path)
{
	struct sockaddr_un addr;
	int sock_fd;
	char buffer[MAX_BUF_LEN];
	int is_tty = isatty(STDIN_FILENO);
	const char *prompt = is_tty ? "--> " : "";

	sock_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (sock_fd < 0) {
		perror("socket creation failed");
		return;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

	if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect failed");
		close(sock_fd);
		return;
	}

	if (is_tty) {
		printf("Connecting to %s\n", sock_path);
	}

	// Read initial response
	if (read_socket(sock_fd, buffer, sizeof(buffer), is_tty, is_tty) < 0) {
		close(sock_fd);
		return;
	}

	// Get max output length and PID from JSON
	char *max_len_str = json_find_value(buffer, "max_output_len");
	char *pid_str = json_find_value(buffer, "pid");

	//size_t max_output_len = max_len_str ? atoi(max_len_str) : MAX_BUF_LEN;
	pid_t pid = pid_str ? atoi(pid_str) : 0;

	free(max_len_str);
	free(pid_str);

	if (is_tty && pid > 0) {
		char *app_name = get_app_name(pid);
		if (app_name) {
			printf("Connected to application: \"%s\"\n", app_name);
			free(app_name);
		}
	}

	// Get list of commands
	if (send(sock_fd, "/", 1, 0) < 0) {
		perror("send failed");
		close(sock_fd);
		return;
	}

	if (read_socket(sock_fd, buffer, sizeof(buffer), 0, 0) == 0) {
		char **commands = NULL;
		size_t count = 0;
		if (parse_commands_array(buffer, "/", &commands, &count) == 0) {
			for (size_t i = 0; i < count && i < MAX_CMDS; i++) {
				g_commands[g_command_count++] = commands[i];
			}
			free(commands);
		}
	}

	// Interactive loop
	char *input = NULL;
	while (1) {
		if(strlen(cmdline_cmd) > 0){
			input = strdup(cmdline_cmd);
			cmdline_cmd[0] = 0;
		}else{
			if (is_tty) {
				input = advanced_readline(prompt);
			} else {
				input = malloc(MAX_BUF_LEN);
				if (!fgets(input, MAX_BUF_LEN, stdin)) {
					free(input);
					break;
				}
				input[strcspn(input, "\n")] = '\0';
			}

		}
		if (!input) break;

		// Handle empty input (just pressing Enter)
		if (strlen(input) == 0) {
			free(input);
			continue;
		}


		if (strcmp(input, "quit") == 0 ||
				strcmp(input, "exit") == 0 || strcmp(input, "q") == 0) {
			free(input);
			break;
		}

		input_map(input);
		adj_input(input);

		if (input[0] == '/') {
			if (send(sock_fd, input, strlen(input), 0) < 0) {
				perror("send failed");
				free(input);
				break;
			}
			read_socket(sock_fd, buffer, sizeof(buffer), 1, is_tty);

			// Add to history if not empty and different from last
			if (is_tty && strlen(input) > 0 && 
					(g_history_count == 0 || strcmp(input, g_history[g_history_count-1]) != 0)) {
				add_to_history(input);
			}
		} else {
			if (is_tty) {
				printf("Unknown command. Commands must start with '/'\n");
			}
		}

		free(input);
	}

	// Cleanup
	cleanup_commands();
	cleanup_history();
	close(sock_fd);
}

/**
 * @brief Parse command line arguments
 */
void parse_arguments(int argc, char *argv[], cmdline_args_t *args)
{
	args->file_prefix = DEFAULT_PREFIX;
	args->instance = 0;
	args->list_mode = 0;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--file-prefix") == 0) {
			if (i + 1 < argc) {
				args->file_prefix = argv[++i];
			}
		} else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--cmd") == 0) {
			if (i + 1 < argc) {
				strcpy(cmdline_cmd, argv[++i]);
			}
		} else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--instance") == 0) {
			if (i + 1 < argc) {
				args->instance = atoi(argv[++i]);
			}
		} else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--list") == 0) {
			args->list_mode = 1;
		} else {
			fprintf(stderr, "Usage: %s [-f file_prefix] [-i instance] [-l]\n", argv[0]);
			fprintf(stderr, "Options:\n");
			fprintf(stderr, "  -f, --file-prefix PREFIX  DPDK file prefix (default: rte)\n");
			fprintf(stderr, "  -i, --instance NUM        Instance number (default: 0)\n");
			fprintf(stderr, "  -l, --list                List available file prefixes\n");
			fprintf(stderr, "  -c, --cmd                 run cmd from cmdline\n");
			exit(EXIT_FAILURE);
		}
	}
}

int main(int argc, char *argv[])
{
	cmdline_args_t args;
	char sock_path[MAX_PATH_LEN];

	parse_arguments(argc, argv, &args);

	if (args.list_mode) {
		list_file_prefixes();
		return EXIT_SUCCESS;
	}

	char *runtime_dir = get_dpdk_runtime_dir(args.file_prefix);
	snprintf(sock_path, sizeof(sock_path), "%s/%s", runtime_dir, SOCKET_NAME);

	if (args.instance > 0) {
		snprintf(sock_path + strlen(sock_path),
				sizeof(sock_path) - strlen(sock_path),
				":%d", args.instance);
	}

	handle_socket(&args, sock_path);
	cleanup_commands();
	cleanup_history();

	return EXIT_SUCCESS;
}
