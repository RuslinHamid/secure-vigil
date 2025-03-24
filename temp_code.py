# Enter original code here
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFFER_SIZE 64

void vulnerable_function(char *user_input) {
    char buffer[BUFFER_SIZE];
    // Buffer Overflow Vulnerability
    strcpy(buffer, user_input);  // No bounds checking
    
    // Format String Vulnerability
    printf(buffer);  // Direct use of user input as format string
    
    // Command Injection Vulnerability
    char command[100];
    sprintf(command, "echo %s", buffer);
    system(command);  // Unsafe system call with user input  // Mitigated Code Injection
}

int main(int argc, char *argv[]) {
    char *user_input;
    if (argc < 2) {
        printf("Usage: %s <input_string>\n", argv[0]);
        return 1;
    }
    
    // Memory Leak Vulnerability
    user_input = (char *)malloc(strlen(argv[1]) + 1);
    strcpy(user_input, argv[1]);
    
    // Integer Overflow Vulnerability
    int size = atoi(user_input);
    char *buf = (char *)malloc(size * sizeof(char));  // Possible integer overflow
    
    vulnerable_function(user_input);
    
    // Use After Free Vulnerability
    free(buf);
    buf[0] = 'A';  // Using buf after freeing
    
    return 0;  // Memory leak: user_input is never freed
} 