#include "cmd.h"

// 初始化命令数组结构体，传入最大命令数量
void init_command_array(command_array_t *cmd_array, int max_commands) {
    cmd_array->commands = (char **)calloc(max_commands, sizeof(char *));
    if (!cmd_array->commands) {
        perror("Failed to allocate memory for command array");
        exit(EXIT_FAILURE);
    }
    
    cmd_array->current_command_count = 0;
    cmd_array->max_command_count = max_commands;  // 使用传入的最大命令数量
}

// 释放命令数组结构体中的动态内存
void free_command_array(command_array_t *cmd_array) {
    if (cmd_array->commands) {
        for (int i = 0; i < cmd_array->current_command_count; ++i) {
            free(cmd_array->commands[i]);
        }
        free(cmd_array->commands);
    }
}

// 执行命令并获取输出
int execute_command(const char *command, char *output, size_t output_size) {
    if (command == NULL || strlen(command) == 0) {
        fprintf(stderr, "Invalid command: command is NULL or empty\n");
        return -1;
    }

    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("pipe");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    } else if (pid == 0) {
        // 子进程执行命令
        close(pipefd[0]);  // 关闭读端
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);

        char *argv[] = {"/bin/sh", "-c", (char *)command, NULL};
        execvp(argv[0], argv);  
        perror("execvp");  // 如果execvp失败
        exit(EXIT_FAILURE);
    } else {
        // 父进程读取输出
        close(pipefd[1]);  // 关闭写端
        ssize_t n;
        size_t total_read = 0;

        while ((n = read(pipefd[0], output + total_read, output_size - total_read - 1)) > 0) {
            total_read += n;
            if (total_read >= output_size - 1) {
                break;  // 确保不超过缓冲区大小
            }
        }

        output[total_read] = '\0';  // 确保以 '\0' 结尾
        close(pipefd[0]);  // 关闭读端

        // 等待子进程结束
        int status;
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            return -1;
        }
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            return 0; // 成功执行
        } else {
            fprintf(stderr, "Error: Command failed with status: %d\n", WEXITSTATUS(status));
            return -1;
        }
    }
}

// 添加命令到命令数组，支持可变参数
void add_command_to_array(command_array_t *cmd_array, const char *command_template, ...) {
    if (cmd_array->current_command_count >= cmd_array->max_command_count) {
        fprintf(stderr, "Error: Command array is full. Cannot add more commands.\n");
        return;
    }

    if (command_template == NULL) {
        fprintf(stderr, "Error: Invalid command template.\n");
        return;
    }

    char command[COMMAND_BUFFER_SIZE] = {0}; // 用于拼接命令

    // 可变参数处理
    va_list args;
    va_start(args, command_template);
    
    // 拼接命令，使用 vsnprintf 来处理可变参数
    vsnprintf(command, sizeof(command), command_template, args);

    va_end(args);

    cmd_array->commands[cmd_array->current_command_count] = strdup(command);
    if (cmd_array->commands[cmd_array->current_command_count] == NULL) {
        perror("Failed to duplicate command string");
        return;
    }

    cmd_array->current_command_count++;  // 更新命令数量
}

// 按顺序执行命令数组中的所有命令
void execute_commands_in_order(command_array_t *cmd_array) {
    for (int i = 0; i < cmd_array->current_command_count; ++i) {
        char output[COMMAND_BUFFER_SIZE];
        printf("Command: %s\n", cmd_array->commands[i]);
        if (execute_command(cmd_array->commands[i], output, sizeof(output)) == 0) {
            // 仅在成功时执行，输出可以在这里处理
        }
    }
}
