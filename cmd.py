import argparse
import sys
from utils import HostsManager, PrivilegeManager


def main():
    parser = argparse.ArgumentParser(
        description="Hosts文件管理工具",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 查看命令
    list_parser = subparsers.add_parser('list', help='列出所有条目')

    # 添加命令
    add_parser = subparsers.add_parser('add', help='添加新条目')
    add_parser.add_argument('ip', help='IP地址')
    add_parser.add_argument('domains', nargs='+', help='域名列表')

    # 删除命令
    del_parser = subparsers.add_parser('delete', help='删除条目')
    del_group = del_parser.add_mutually_exclusive_group(required=True)
    del_group.add_argument('--ip', help='按IP删除')
    del_group.add_argument('--domain', help='按域名删除')

    # 权限检查
    if not PrivilegeManager.is_admin():
        print("需要管理员权限，尝试提权...")
        PrivilegeManager.elevate()

    # macOS特殊处理
    if platform.system() == 'Darwin' and PrivilegeManager.check_macos_flags():
        print("检测到系统文件锁，正在解除...")
        PrivilegeManager.unlock_macos_hosts(None)

    args = parser.parse_args()

    try:
        if args.command == 'list':
            with open(HostsManager.get_hosts_path(), 'r') as f:
                print(f.read())

        elif args.command == 'add':
            new_entry = f"{args.ip} {' '.join(args.domains)}\n"
            with open(HostsManager.get_hosts_path(), 'a') as f:
                f.write(new_entry)
            print("条目已添加")

        elif args.command == 'delete':
            with open(HostsManager.get_hosts_path(), 'r') as f:
                lines = f.readlines()

            new_lines = []
            for line in lines:
                if args.ip and line.startswith(args.ip):
                    continue
                if args.domain and args.domain in line.split()[1:]:
                    continue
                new_lines.append(line)

            with open(HostsManager.get_hosts_path(), 'w') as f:
                f.writelines(new_lines)
            print("条目已删除")

    except PermissionError:
        print("权限不足，请以管理员权限运行")
        sys.exit(1)
    except Exception as e:
        print(f"错误: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()