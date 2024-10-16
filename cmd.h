#ifndef CMD_H
#define CMD_H 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <stdarg.h>  // 添加可变参数支持

#define COMMAND_BUFFER_SIZE 256  // 设置缓冲区大小

typedef struct {
    char **commands;                   // 存储命令的数组
    int current_command_count;         // 当前命令数量
    int max_command_count;             // 最大命令数量
} command_array_t;

// 初始化命令数组结构体，传入最大命令数量
void init_command_array(command_array_t *cmd_array, int max_commands);

// 释放命令数组结构体中的动态内存
void free_command_array(command_array_t *cmd_array);

// 执行命令并获取输出
int execute_command(const char *command, char *output, size_t output_size);

// 添加命令到命令数组，支持可变参数
void add_command_to_array(command_array_t *cmd_array, const char *command_template, ...);

// 按顺序执行命令数组中的所有命令
void execute_commands_in_order(command_array_t *cmd_array);

#endif // CMD_H
