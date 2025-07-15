import os
import sys
import platform
import shutil
import ctypes
import subprocess
import tempfile
from pathlib import Path
from tkinter import messagebox
import socket


class HostsManager:
    @staticmethod
    def get_hosts_path():
        """获取跨平台hosts文件路径"""
        system = platform.system()
        if system == "Windows":
            return r"C:\Windows\System32\drivers\etc\hosts"
        elif system in ["Linux", "Darwin"]:
            return "/etc/hosts"
        else:
            raise OSError("Unsupported OS")

    @staticmethod
    def backup_hosts():
        """创建备份文件"""
        src = HostsManager.get_hosts_path()
        dst = f"{src}.bak_{int(tempfile._get_default_tempdir().split('_')[-1])}"
        shutil.copyfile(src, dst)
        return dst

    @staticmethod
    def validate_content(content):
        """验证hosts内容格式"""
        lines = content.split('\n')
        for line in lines:
            if line.strip() and not line.startswith('#'):
                parts = line.split()
                if len(parts) < 2 or not parts[0].count('.') == 3:
                    raise ValueError(f"Invalid entry: {line}")
        return True

    @staticmethod
    def safe_write(content):
        """安全写入方法"""
        HostsManager.validate_content(content)
        tmp_path = f"{HostsManager.get_hosts_path()}.tmp"
        with open(tmp_path, 'w', encoding='utf-8') as f:
            f.write(content)
        os.replace(tmp_path, HostsManager.get_hosts_path())

    def parse_hosts():
        """解析hosts文件为结构化数据

        返回:
            List[Dict]: 结构化条目列表，每个字典包含:
                'ip' (str): IP地址
                'domains' (List[str]): 关联域名列表
                'comment' (str): 行尾注释（可选）

        实现要点:
            1. 跳过空行和全注释行
            2. 处理行内注释
            3. 支持IPv4/IPv6地址
            4. 兼容多空格/TAB分隔
        """
        entries = []
        path = HostsManager.get_hosts_path()

        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                # 跳过空行和全注释行
                if not line or line.startswith('#'):
                    continue

                # 拆分主内容与行尾注释
                if '#' in line:
                    content, comment = line.split('#', 1)
                    comment = comment.strip()
                else:
                    content, comment = line, ''

                parts = content.split()
                if len(parts) < 2:
                    continue  # 无效条目

                ip = parts[0]
                domains = []

                # 验证IP格式
                if not (HostsManager.is_valid_ipv4(ip) or HostsManager.is_valid_ipv6(ip)):
                    continue

                # 提取有效域名
                for part in parts[1:]:
                    if '#' in part:  # 处理中间出现的注释
                        break
                    if '.' in part or ':' in part:  # 基础域名验证
                        domains.append(part)

                if domains:
                    entries.append({
                        'ip': ip,
                        'domains': domains,
                        'comment': comment,
                        'line_number': line_num
                    })

        return entries

    @staticmethod
    def is_valid_ipv4(ip):
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except socket.error:
            return False

    @staticmethod
    def is_valid_ipv6(ip):
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False


class PrivilegeManager:
    @staticmethod
    def is_admin():
        """跨平台权限验证"""
        try:
            if platform.system() == 'Windows':
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except:
            return False

    @staticmethod
    def elevate():
        """GUI权限提升"""
        system = platform.system()
        script = os.path.abspath(sys.argv[0])

        if system == 'Windows':
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, script, None, 1)
        elif system == 'Darwin':
            subprocess.run([
                'osascript', '-e',
                f'do shell script "python3 {script}" '
                f'with administrator privileges '
                f'without altering line endings'
            ])
        elif system == 'Linux':
            subprocess.run(['pkexec', sys.executable, script])
        sys.exit(0)

    @staticmethod
    def check_macos_flags():
        """检测macOS文件锁"""
        if platform.system() != 'Darwin':
            return False

        try:
            output = subprocess.check_output(
                ["ls", "-lO", HostsManager.get_hosts_path()],
                stderr=subprocess.STDOUT
            ).decode()
            return 'schg' in output or 'uchg' in output
        except subprocess.CalledProcessError:
            return False

    @staticmethod
    def unlock_macos_hosts(parent):
        """解除macOS文件锁"""
        cmds = [
            ["sudo", "chflags", "nouchg", HostsManager.get_hosts_path()],
            ["sudo", "chflags", "noschg", HostsManager.get_hosts_path()]
        ]

        try:
            for cmd in cmds:
                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT
                )
                out, _ = proc.communicate(timeout=10)
                if proc.returncode != 0:
                    raise Exception(out.decode())
            return True
        except Exception as e:
            messagebox.showerror("解锁失败",
                                 f"错误: {str(e)}\n请手动执行:\n"
                                 f"sudo chflags nouchg /etc/hosts\n"
                                 f"sudo chflags noschg /etc/hosts",
                                 parent=parent)
            return False
