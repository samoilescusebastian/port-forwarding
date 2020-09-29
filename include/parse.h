#ifndef __PARSE_H__
#define __PARSE_H__

#define FALSE 0
#define TRUE 1

#include "structs.h"
#include <stdlib.h>
#include <stdio.h>



int get_lines_number(FILE*);

void convert_to_r_entry(char*, struct r_table_entry*, int);

int parse_route_table(struct r_table_entry**, int *);

#endif // !