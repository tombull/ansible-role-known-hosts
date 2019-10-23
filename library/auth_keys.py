#!/usr/bin/python -tt

import socket
from subprocess import check_output
import os
import fcntl


class AuthorisedKeys:
    def __init__(self, module):
        self.servers = module.params["servers"]

    def set_auth_keys(self):
        servers_list = []
        for server in self.servers:
            if not server:
                continue
            if AuthorisedKeys.is_valid_ipv4_address(server):
                servers_list.append(server)
            else:
                try:
                    server_info = socket.gethostbyname_ex(server)
                except socket.error:
                    continue
                servers_list.append(server)
                servers_list.extend(server_info[2])

        servers_and_keys = {}
        for server in servers_list:
            auth_key = check_output(["ssh-keyscan", "-t", "rsa", server]).decode("utf-8")
            servers_and_keys[server] = auth_key

        changed_any = False

        for keys_file in ["/etc/ssh/ssh_known_hosts", "~/.ssh/known_hosts"]:
            changed_this = False
            working_file = os.path.abspath(os.path.expanduser(keys_file))
            if os.path.exists(working_file) and os.path.isfile(working_file):

                with open(working_file, "r+") as open_file:
                    while True:
                        try:
                            fcntl.flock(open_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                            break
                        except IOError as e:
                            if e.errno != errno.EAGAIN:
                                raise
                            else:
                                time.sleep(0.1)
                    file_lines = list(open_file)
                    while file_lines[-1].isspace() or not file_lines[-1]:
                        del file_lines[-1]

                    for server, auth_key in list(servers_and_keys.items()):
                        entries_in_file = [
                            file_line for file_line in file_lines if server.lower() in [address.lower() for address in file_line.split(" ")[0].split(",")]
                        ]
                        incorrect_entries_in_file = [file_line for file_line in entries_in_file if file_line != auth_key]
                        if len(entries_in_file) != 1 or len(incorrect_entries_in_file) > 0:
                            file_lines = [
                                file_line
                                for file_line in file_lines
                                if not server.lower() in [address.lower() for address in file_line.split(" ")[0].split(",")]
                            ]
                            file_lines.append(auth_key)
                            changed_this = True

                    if changed_this:
                        open_file.seek(0)
                        open_file.writelines(file_lines)
                        changed_any = True

                    fcntl.flock(open_file.fileno(), fcntl.LOCK_UN)

        return changed_any

    @staticmethod
    def is_valid_ipv4_address(address):
        try:
            socket.inet_pton(socket.AF_INET, address)
        except AttributeError:  # no inet_pton here, sorry
            try:
                socket.inet_aton(address)
            except socket.error:
                return False
            return address.count(".") == 3
        except socket.error:  # not a valid address
            return False
        return True


def main():
    module = AnsibleModule(argument_spec=dict(servers=dict(type="list", required=True)))

    obj = AuthorisedKeys(module)

    is_changed = obj.set_auth_keys()

    module.exit_json(changed=is_changed)


from ansible.module_utils.basic import *

if __name__ == "__main__":
    main()
