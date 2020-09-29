#include "include/parse.h"
int get_lines_number(FILE *file) {
	int lines = 0;
	for(char c = getc(file); c != EOF; c = getc(file)) {
		if (c == '\n') {
			lines = lines + 1;
		}
	}
	fseek(file, 0, SEEK_SET);
	return lines;
}

void convert_to_r_entry(char *buffer, struct r_table_entry *rtable, int index) {

	buffer[strlen(buffer) - 1] = '\0';
	char *pointer = strtok(buffer, " ");

	inet_pton(AF_INET, pointer, &(rtable[index].prefix));
	pointer = strtok(NULL, " ");

	inet_pton(AF_INET, pointer, &(rtable[index].next_hp));
	pointer = strtok(NULL, " ");
	
	inet_pton(AF_INET, pointer, &(rtable[index].mask));
	pointer = strtok(NULL, " ");
	
	rtable[index].interface = atoi(pointer);
}

int parse_route_table(struct r_table_entry **table, int *r_table_length) {

	FILE* routing_file = fopen("rtable.txt", "r");
	if (routing_file == NULL) {
		return FALSE;
	}

	(*r_table_length) = get_lines_number(routing_file);

	(*table) = malloc(sizeof(struct r_table_entry) * (*r_table_length));
	if (*table == NULL) {
		return FALSE;
	}

	size_t line_length = 64;
	char *buffer = malloc(line_length);
	if (buffer == NULL) {
		return FALSE;
	}
	int i = 0;
	while(fgets(buffer, line_length, routing_file)) {
		convert_to_r_entry(buffer, *table, i++);
	}
	
	free(buffer);
	fclose(routing_file);
	return TRUE;
	
}
