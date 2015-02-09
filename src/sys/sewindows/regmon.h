#pragma once

#define  OP_REG_READ						1  // 注册表读
#define  OP_REG_DELETE_VALUE_KEY			3  // 删除键值
#define  OP_REG_CREATE_KEY                  4  // 创建键
#define  OP_REG_SET_VALUE_KEY				5  // 设置键值
#define  OP_REG_RENAME						6  // 重命名
#define  OP_REG_DELETE_KEY                  7  // 删除键
#define  OP_REG_SAVE						8  // 保存
#define  OP_REG_RESTORE						9 // 恢复
#define  OP_REG_REPLACE						10 // 替换
#define  OP_REG_LOAD						11 // 加载
#define  OP_REG_UNLOAD						12 // 卸载

NTSTATUS sw_register_init(PDRIVER_OBJECT pDriverObject);
NTSTATUS sw_register_uninit(PDRIVER_OBJECT pDriverObject);
NTSTATUS sw_get_current_user(WCHAR *srcPath, int len);
int sw_regisster_make_path(WCHAR * path, ULONG lenstr);
