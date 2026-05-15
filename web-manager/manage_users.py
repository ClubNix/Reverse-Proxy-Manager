#!/usr/bin/env python3
"""
CLI for managing users in the Reverse Proxy Manager auth database.

Usage (inside the container):
    python manage_users.py list
    python manage_users.py add <username>
    python manage_users.py passwd <username>
    python manage_users.py delete <username>
    python manage_users.py reset-totp <username>
"""

import sys
import os
import getpass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db import init_db, user_count, get_user, get_all_users, create_user, \
    update_password, set_totp_secret, delete_user
from werkzeug.security import generate_password_hash

USAGE = """
Usage: python manage_users.py <command> [args]

Commands:
  list                    List all users
  add <username>          Create a new user
  passwd <username>       Change a user's password
  delete <username>       Delete a user
  reset-totp <username>   Disable TOTP for a user
"""


def cmd_list():
    users = get_all_users()
    if not users:
        print('No users found.')
        return
    print(f"  {'ID':>3}  {'Username':<30}  {'2FA':<5}  Created")
    print('  ' + '-' * 60)
    for u in users:
        totp = '2FA  ' if u['has_totp'] else '     '
        print(f"  {u['id']:>3}  {u['username']:<30}  {totp}  {u['created_at']}")


def cmd_add(username: str):
    if get_user(username):
        print(f'Error: user "{username}" already exists.')
        sys.exit(1)
    password = getpass.getpass(f'Password for {username}: ')
    if not password:
        print('Error: password cannot be empty.')
        sys.exit(1)
    if password != getpass.getpass('Confirm password: '):
        print('Error: passwords do not match.')
        sys.exit(1)
    create_user(username, generate_password_hash(password))
    print(f'User "{username}" created.')


def cmd_passwd(username: str):
    user = get_user(username)
    if not user:
        print(f'Error: user "{username}" not found.')
        sys.exit(1)
    password = getpass.getpass(f'New password for {username}: ')
    if not password:
        print('Error: password cannot be empty.')
        sys.exit(1)
    if password != getpass.getpass('Confirm password: '):
        print('Error: passwords do not match.')
        sys.exit(1)
    update_password(user['id'], generate_password_hash(password))
    print(f'Password updated for "{username}".')


def cmd_delete(username: str):
    user = get_user(username)
    if not user:
        print(f'Error: user "{username}" not found.')
        sys.exit(1)
    if input(f'Delete user "{username}"? [y/N] ').lower() != 'y':
        print('Aborted.')
        return
    delete_user(user['id'])
    print(f'User "{username}" deleted.')


def cmd_reset_totp(username: str):
    user = get_user(username)
    if not user:
        print(f'Error: user "{username}" not found.')
        sys.exit(1)
    set_totp_secret(user['id'], None)
    print(f'TOTP disabled for "{username}".')


def main():
    init_db()
    args = sys.argv[1:]
    if not args:
        print(USAGE)
        sys.exit(1)

    cmd = args[0]
    if cmd == 'list' and len(args) == 1:
        cmd_list()
    elif cmd == 'add' and len(args) == 2:
        cmd_add(args[1])
    elif cmd == 'passwd' and len(args) == 2:
        cmd_passwd(args[1])
    elif cmd == 'delete' and len(args) == 2:
        cmd_delete(args[1])
    elif cmd == 'reset-totp' and len(args) == 2:
        cmd_reset_totp(args[1])
    else:
        print(USAGE)
        sys.exit(1)


if __name__ == '__main__':
    main()
