#include "cmd.h"

int main() {
    command_array_t cmd_array;
    init_command_array(&cmd_array, 10); // 传入最大命令数量

    // 使用可变参数添加命令
    add_command_to_array(&cmd_array, "echo Hello, %s %s", 2, "World", "!");
    add_command_to_array(&cmd_array, "ls %s %s", 2, "-l", "-a");

    // 测试添加超过最大命令数量的命令将触发错误
    for (int i = 0; i < 11; i++) { // 尝试添加11个命令
        char command[BUFFER_SIZE];
        snprintf(command, sizeof(command), "echo Command number %d", i + 1);
        add_command_to_array(&cmd_array, command, 0);  // 这里传0表示没有变量
    }
    
    execute_commands_in_order(&cmd_array);
    free_command_array(&cmd_array);

    return 0;
}
