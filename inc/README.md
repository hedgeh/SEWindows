# SEWindows SDK使用文档

## SDK说明
		在Windows上建立一个开源的强制访问控制框架及SDK。使Windows平台的应用开发者，
		可以不用关心操作系统底层技术，只用进行简单的SDK调用或配置就可以保护自己的应用程序。

## 接口说明

### SDK依赖文件
		1、sewindows.sys  驱动
		2、sewindows.dll  动态库
		3、sewindows.h    头文件

### SDK::初始化
		/**
		 * sewin_init : init sewindows
		 *
		 * return :  TRUE  - success
		 *           FALSE - Failed
		 */
		SEWINDOWS_API BOOLEAN sewin_init(void);

		使用SDK之前，需要先调用初始化函数
		
### SDK::设置工作模式
		/**
		 * sewin_setoption : set working mode
		 *
		 * @param mode : SEWIN_MODE_INTERCEPT or SEWIN_MODE_NOTIFY
		 * @param type : SEWIN_TYPE_FILE | SEWIN_TYPE_FROC | SEWIN_TYPE_REG
		 *
		 * return :  TRUE  - success
		 *           FALSE - Failed
		 */
		SEWINDOWS_API BOOLEAN sewin_setoption(int mode, int type);

		SDK的工作模式(mode)有两种：
		1、拦截模式 SEWIN_MODE_INTERCEPT
		   拦截模式下，SDK会根据sewin_operations.function()的返回值决定对某个
		   操作“放行”或者“拦截”。
		2、通知模式 SEWIN_MODE_NOTIFY
		   通知模式下，SDK只会将sewin_operations.function()的操作信息进行通知，
		   不会根据返回值进行拦截。

		SDK需要可以处理的类型(type)有三种：
		1、文件（夹）SEWIN_TYPE_FILE
		   对sewin_operations.file_XXX和sewin_operations.dir_XXX有效
		2、进程 SEWIN_TYPE_FROC
		   对sewin_operations.process_XXX有效
		3、注册表 SEWIN_TYPE_REG
		   对sewin_operations.reg_XXX有效
		type支持‘或’操作，即下面情形是合法的：type = SEWIN_TYPE_FILE | SEWIN_TYPE_FROC | SEWIN_TYPE_REG


### SDK::注册自定义处理函数
		/**
		 * sewin_register_opt : register callback functions
		 *
		 * @param ops : sewin_operations
		 *
		 * return :  TRUE  - success
		 *           FALSE - Failed
		 */
		SEWINDOWS_API BOOLEAN sewin_register_opt(struct sewin_operations *ops);
		
		将自定义的函数进行注册(每个SDK中，只能有一份注册函数)，例如:
		struct sewin_operations my_ops;
		my_ops.file_create = my_file_create;
		sewin_register_opt(&my_ops);
		
		my_file_create函数需要用户自己实现，根据自定义的规则，将自己的程序保护起来。
		在拦截模式下:
		my_file_create函数返回TRUE，该操作会正常执行；返回FALSE，该操作会被拦截。
		在通知模式下：
		my_file_create函数返回TRUE或者FALSE，该操作都会正常执行。


		struct sewin_operations {
		    // 文件 - 创建
		    BOOLEAN(*file_create)           (WCHAR *user_name, WCHAR *process, WCHAR *file_path);
		    // 文件 - 删除
		    BOOLEAN(*file_unlink)           (WCHAR *user_name, WCHAR *process, WCHAR *file_path);
		    // 文件 - 设置属性
		    BOOLEAN(*file_set_attr)         (WCHAR *user_name, WCHAR *process, WCHAR *file_path, PFILE_BASIC_INFORMATION pfbi);
		    // 文件 - 读
		    BOOLEAN(*file_read)             (WCHAR *user_name, WCHAR *process, WCHAR *file_path);
		    // 文件 - 写
		    BOOLEAN(*file_write)            (WCHAR *user_name, WCHAR *process, WCHAR *file_path);
		    // 文件 - 重命名
		    BOOLEAN(*file_rename)           (WCHAR *user_name, WCHAR *process, WCHAR *src_file, WCHAR *new_name);
		    // 文件 - 执行
		    BOOLEAN(*file_execute)          (WCHAR *user_name, WCHAR *process, WCHAR *file_path);
		
		    // 文件夹 - 创建
		    BOOLEAN(*dir_create)            (WCHAR *user_name, WCHAR *process, WCHAR *dir_path);
		    // 文件夹 - 删除
		    BOOLEAN(*dir_unlink)            (WCHAR *user_name, WCHAR *process, WCHAR *dir_path);
		    // 文件夹 - 设置属性
		    BOOLEAN(*dir_set_attr)          (WCHAR *user_name, WCHAR *process, WCHAR *dir_path, PFILE_BASIC_INFORMATION pfbi);
		    // 文件夹 - 重命名
		    BOOLEAN(*dir_rename)            (WCHAR *user_name, WCHAR *process, WCHAR *src_dir, WCHAR *new_name);
		
		    // 进程 - 创建
		    BOOLEAN(*process_create)        (WCHAR *user_name, WCHAR *process, WCHAR *dst_proc);
		    // 进程 - 线程创建
		    BOOLEAN(*process_create_thread) (WCHAR *user_name, WCHAR *process, WCHAR *dst_proc);
		    // 进程 - 进程结束
		    BOOLEAN(*process_kill)          (WCHAR *user_name, WCHAR *process, WCHAR *dst_proc);
		    // 进程 - 读取内存
		    BOOLEAN(*process_read_mem)      (WCHAR *user_name, WCHAR *process, WCHAR *dst_proc);
		    // 进程 - 修改内存
		    BOOLEAN(*process_write_mem)     (WCHAR *user_name, WCHAR *process, WCHAR *dst_proc);
		    // 进程 - 设置属性
		    BOOLEAN(*process_set_mem_attr)  (WCHAR *user_name, WCHAR *process, WCHAR *dst_proc);
		
		    // 注册表 - 创建项
		    BOOLEAN(*reg_create_key)        (WCHAR *user_name, WCHAR *process, WCHAR *reg_path);
		    // 注册表 - 删除项
		    BOOLEAN(*reg_delete_key)        (WCHAR *user_name, WCHAR *process, WCHAR *reg_path);
		    // 注册表 - 枚举项
		    BOOLEAN(*reg_enum_key)          (WCHAR *user_name, WCHAR *process, WCHAR *reg_path);
		    // 注册表 - 重命名项
		    BOOLEAN(*reg_rename_key)        (WCHAR *user_name, WCHAR *process, WCHAR *src_path, WCHAR *new_name);
		    // 注册表 - 设置值
		    BOOLEAN(*reg_set_value)         (WCHAR *user_name, WCHAR *process, WCHAR *reg_path, WCHAR *reg_value);
		    // 注册表 - 删除值
		    BOOLEAN(*reg_delete_value)      (WCHAR *user_name, WCHAR *process, WCHAR *reg_path);
		    // 注册表 - 读取项
		    BOOLEAN(*reg_read_key)          (WCHAR *user_name, WCHAR *process, WCHAR *reg_path);
		    // 注册表 - 枚举值
		    BOOLEAN(*reg_enum_value)        (WCHAR *user_name, WCHAR *process, WCHAR *reg_path);
		    // 注册表 - 导出文件
		    BOOLEAN(*reg_save_key)          (WCHAR *user_name, WCHAR *process, WCHAR *reg_path);
		    // 注册表 - 从文件导入
		    BOOLEAN(*reg_restore_key)       (WCHAR *user_name, WCHAR *process, WCHAR *reg_path);
		    // 注册表 - 替换
		    BOOLEAN(*reg_replace)           (WCHAR *user_name, WCHAR *process, WCHAR *reg_path);
		    // 注册表 - 从磁盘加载注册表文件
		    BOOLEAN(*reg_load_key)          (WCHAR *user_name, WCHAR *process, WCHAR *reg_path);
		    // 注册表 - 导出注册表项到磁盘
		    BOOLEAN(*reg_unload_key)        (WCHAR *user_name, WCHAR *process, WCHAR *reg_path);
		};
		
		参数说明：
		@param user_name  当前操作的用户名
		@param process    当前操作的进程
		
		@param file_path  当前被操作的文件路径
		@param dir_path   当前被操作的文件夹路径
		@param reg_path   当前被操作的注册表路径
		
		@param src_file   当前被操作的原始文件路径
		@param new_name   当前被操作的目标文件（夹/注册表）路径
		@param src_dir    当前被操作的目标文件夹路径
		
		@param reg_path   当前被操作的原始注册表路径
		@param pfbi       属性值
		@param reg_value  注册表值


### SDK::完整示例请参照
		https://github.com/hedgeh/SEWindows/blob/develop/examples/notify_example/notify_example.cpp
		https://github.com/hedgeh/SEWindows/blob/develop/examples/intercept_example/intercept_example.cpp
		