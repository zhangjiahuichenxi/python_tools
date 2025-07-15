import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from utils import HostsManager, PrivilegeManager
import platform

class HostsEditor(tk.Tk):
    def __init__(self):
        self._security_check()
        super().__init__()
        self.title("Hosts编辑器")
        self.geometry("1000x600")
        self._init_ui()
        self._load_data()
        self.mainloop()

    def _init_ui(self):
        """界面初始化"""
        # 工具栏
        self.toolbar = ttk.Frame(self)
        ttk.Button(self.toolbar, text="添加", command=self._add_entry).pack(side=tk.LEFT, padx=2)
        ttk.Button(self.toolbar, text="删除", command=self._delete_entry).pack(side=tk.LEFT, padx=2)
        ttk.Button(self.toolbar, text="编辑", command=self._edit_entry).pack(side=tk.LEFT, padx=2)
        ttk.Separator(self.toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)
        ttk.Button(self.toolbar, text="保存", command=self._save).pack(side=tk.LEFT, padx=2)
        ttk.Button(self.toolbar, text="备份", command=self._backup).pack(side=tk.LEFT, padx=2)
        self.toolbar.pack(fill=tk.X, pady=5)

        # 表格
        self.tree = ttk.Treeview(self, columns=('ip', 'domains'), show='headings')
        self.tree.heading('ip', text='IP地址', anchor=tk.W)
        self.tree.heading('domains', text='域名列表', anchor=tk.W)
        self.tree.column('ip', width=150, minwidth=100)
        self.tree.column('domains', width=800, minwidth=200)

        # 滚动条
        scroll = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(expand=True, fill=tk.BOTH)

        # 右键菜单
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="编辑", command=self._edit_entry)
        self.menu.add_command(label="删除", command=self._delete_entry)
        self.tree.bind("<Button-3>", self._show_context_menu)

    def _load_data(self):
        """加载数据到表格"""
        entries = HostsManager.parse_hosts()
        for entry in entries:
            self.tree.insert('', tk.END, values=(entry['ip'], ' '.join(entry['domains'])))

    def _add_entry(self):
        """添加新条目"""
        dialog = EntryDialog(self, "添加新条目")
        if dialog.result:
            self.tree.insert('', tk.END, values=(dialog.ip, dialog.domains))

    def _show_context_menu(self, event):
        """显示表格右键上下文菜单

        参数:
            event (tk.Event): 鼠标事件对象，包含触发位置信息

        功能说明:
            1. 精确定位到鼠标下方的表格行
            2. 选中当前行作为操作目标
            3. 在光标位置弹出上下文菜单
            4. 根据选中状态动态更新菜单项
        """
        # 定位鼠标下方的行
        row_id = self.tree.identify_row(event.y)

        if row_id:
            # 清除当前选择并选中当前行
            self.tree.selection_remove(self.tree.selection())
            self.tree.selection_add(row_id)

            # 高亮当前行
            self.tree.focus(row_id)

            # 动态更新菜单项状态
            self._update_menu_items()

            # 显示上下文菜单
            try:
                self.menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.menu.grab_release()

        # 阻止默认右键菜单
        return "break"

    def _update_menu_items(self):
        """更新菜单项可用状态

        功能扩展点:
            - 根据选中行的数据类型启用不同菜单项
            - 处理多选时的批量操作限制
            - 显示与选中内容相关的动态选项
        """
        selected_count = len(self.tree.selection())

        # 批量删除始终可用
        self.menu.entryconfig("删除", state=tk.NORMAL)

        # 单行操作功能限制
        if selected_count != 1:
            self.menu.entryconfig("编辑", state=tk.DISABLED)
            self.menu.entryconfig("复制IP", state=tk.DISABLED)
            self.menu.entryconfig("复制域名", state=tk.DISABLED)
        else:
            values = self.tree.item(self.tree.selection()[0], 'values')
            self.menu.entryconfig("编辑", state=tk.NORMAL)
            self.menu.entryconfig("复制IP", state=tk.NORMAL if values[0] else tk.DISABLED)
            self.menu.entryconfig("复制域名", state=tk.NORMAL if values[1] else tk.DISABLED)
    def _edit_entry(self):
        """编辑选中条目"""
        selected = self.tree.selection()
        if not selected:
            return
        values = self.tree.item(selected[0], 'values')
        dialog = EntryDialog(self, "编辑条目", initial_ip=values[0], initial_domains=values[1])
        if dialog.result:
            self.tree.item(selected[0], values=(dialog.ip, dialog.domains))

    def _delete_entry(self):
        """删除选中条目"""
        for item in self.tree.selection():
            self.tree.delete(item)

    def _load_content(self):
        try:
            with open(HostsManager.get_hosts_path(), 'r') as f:
                self.editor.delete(1.0, tk.END)
                self.editor.insert(tk.END, f.read())
        except Exception as e:
            messagebox.showerror("加载失败", str(e))

    def _backup(self):
        try:
            backup_path = HostsManager.backup_hosts()
            messagebox.showinfo("备份成功", f"备份文件已创建：\n{backup_path}")
        except Exception as e:
            messagebox.showerror("备份失败", str(e))

    def _save(self):
        """保存表格内容到文件"""
        try:
            content = ""
            for child in self.tree.get_children():
                ip, domains = self.tree.item(child, 'values')
                content += f"{ip}\t{domains}\n"

            HostsManager.safe_write(content)
            messagebox.showinfo("保存成功", "hosts文件已更新")
        except Exception as e:
            messagebox.showerror("保存失败", str(e))

    def _ask_elevation(self):
        return messagebox.askyesno(
            "需要管理员权限",
            "此操作需要管理员权限，是否立即提升权限？",
            icon='warning'
        )

    def _security_check(self):
        """多层安全验证"""
        if not PrivilegeManager.is_admin():
            if self._ask_elevation():
                PrivilegeManager.elevate()
            else:
                self._init_readonly()
                return

        if platform.system() == 'Darwin':
            self._handle_macos_locks()

    def _handle_macos_locks(self):
        """处理macOS特性"""
        if PrivilegeManager.check_macos_flags():
            if messagebox.askyesno(
                    "系统保护检测",
                    "检测到系统级文件锁，需要解除才能编辑\n是否立即解除？"
            ):
                if not PrivilegeManager.unlock_macos_hosts(self):
                    self._init_readonly()

    def _init_readonly(self):
        self.editor.config(state=tk.DISABLED)
        messagebox.showwarning(
            "只读模式",
            "权限不足，当前处于只读模式"
        )
class EntryDialog(simpledialog.Dialog):
    """自定义输入对话框 """

    def __init__(self, parent, title, initial_ip="", initial_domains=""):
        self.ip = initial_ip
        self.domains = initial_domains
        self.result = False
        super().__init__(parent, title)

    def body(self, frame):
        ttk.Label(frame, text="IP地址:").grid(row=0, sticky=tk.W)
        self.ip_entry = ttk.Entry(frame)
        self.ip_entry.insert(0, self.ip)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=2)

        ttk.Label(frame, text="域名（空格分隔）:").grid(row=1, sticky=tk.W)
        self.domain_entry = ttk.Entry(frame)
        self.domain_entry.insert(0, self.domains)
        self.domain_entry.grid(row=1, column=1, padx=5, pady=2)
        return frame

    def apply(self):
        self.ip = self.ip_entry.get()
        self.domains = self.domain_entry.get()
        self.result = True



HostsEditor()
