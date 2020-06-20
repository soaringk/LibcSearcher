#!/usr/bin/env python

from __future__ import print_function
import os
import re
import sys


class LibcSearcher(object):
    """A wrapper used to search for the libc version based on the leaked
    libc function address, incorporation with libc-database.

    Args:
        func (str, optional): name of the leaked function. Defaults to None.
        address (int, optional): address of the leaked function. Defaults to None.

    Examples:
        >>> obj = LibcSearcher("fgets", 0X7ff39014bd90)

        >>> obj.dump("system")      # the offset of `system` in libc
        >>> obj.dump("str_bin_sh")  # the offset of '/bin/sh' in libc
        >>> obj.dump("__libc_start_main_ret")
    """
    def __init__(self, func=None, address=None):
        db_search_path = [
            os.path.join(os.path.realpath(os.path.dirname(__file__)),
                         "libc-database/db/")
        ]
        db_search_path.append('/opt/LibcSearcher/libc-database/db/')
        for path in db_search_path:
            if os.path.exists(path):
                self.libc_database_path = path
        if not self.libc_database_path:
            print("Did you have the libc-database at the right place?")
            print("Searching for db at:\n\t" + '\n\t'.join(db_search_path))
        self.condition = {}
        if func is not None and address is not None:
            self.add_condition(func, address)
        self.db = ""

    def add_condition(self, func, address):
        """Add another condition to narrow down the options

        Args:
            func (str): name of the leaked function
            address (int): address of the leaked function

        Returns:
            LibcSearcher: make cascading possibly

        Examples:
            >>> obj.add_condition('_IO_2_1_stdout_', 0x7ffff7dd2620).add_condition(
                    "write", 0x7ffff7b042b0)
        """
        if not isinstance(func, str):
            print("[-] The function should be a string")
            sys.exit()
        if not isinstance(address, int):
            print("[-] The address should be an int number")
            sys.exit()
        self.condition[func] = address
        return self

    def decided(self):
        """Decide libc version based on conditions

        Wrapper for libc-database's `find` shell script.
        """
        if len(self.condition) == 0:
            print("[-] No leaked info provided, please supply more info:")
            print("\tadd_condition(leaked_func, leaked_address)")
            sys.exit(0)

        res = []
        for name, address in self.condition.items():
            addr_last12 = address & 0xfff
            res.append(re.compile("^%s .*%x" % (name, addr_last12)))

        db = self.libc_database_path
        files = []
        # only read "*.symbols" file to find
        for _, _, f in os.walk(db):
            for i in f:
                files += re.findall('^.*symbols$', i)

        result = {}
        for ff in files:
            fd = open(db + ff, "rb")
            data = fd.read().decode(errors='ignore').split("\n")
            for x in res:
                if any(map(lambda line: x.match(line), data)):
                    try:
                        result[ff] += 1
                    except KeyError:
                        result[ff] = 1
            fd.close()

        result = sorted(result.items(), key=lambda x: x[1], reverse=True)

        if len(result) == 0:
            print("[-] No matched libc, please add more libc or try others")
            sys.exit(0)

        if len(result) > 1:
            print("[+] Multi Results:")
            for x in range(len(result)):
                print("%2d: [hit %2d times] - %s" %
                      (x, result[x][1], self.pmore(result[x][0])))
            print("[*] Please supply more info:")
            print("\tadd_condition(leaked_func, leaked_address)\n")
            while True:
                in_id = input(
                    "[*] You can choose it by hand, or type 'exit' to quit: ")
                if in_id == "exit" or in_id == "quit":
                    sys.exit(0)
                try:
                    in_id = int(in_id)
                    self.db = result[in_id][0]
                    break
                except:
                    continue
        else:
            self.db = result[0][0]
        print("[+] %s be choosed." % self.pmore(self.db))

    def pmore(self, result):
        result = result[:-8]  # .strip(".symbols")
        fd = open(self.libc_database_path + result + ".info")
        info = fd.read().strip()
        return ("%s (id %s)" % (info, result))

    def dump(self, func=None):
        """Wrapper for libc-database's `dump` shell script

        Args:
            func (str, optional): the function to be dumped. Defaults to None.

        Returns:
            int: address of the dumped function in libc
        """
        if not self.db:
            self.decided()
        db = self.libc_database_path + self.db
        fd = open(db, "rb")
        data = fd.read().decode(errors='ignore').strip("\n").split("\n")
        if not func:
            result = {}
            func = [
                "__libc_start_main_ret", "system", "dup2", "read", "write",
                "str_bin_sh"
            ]
            for ff in func:
                for d in data:
                    f = d.split(" ")[0]
                    addr = d.split(" ")[1]
                    if ff == f:
                        result[ff] = int(addr, 16)
            for k, v in result.items():
                print(k, hex(v))
            return result

        for d in data:
            f = d.split(" ")[0]
            addr = d.split(" ")[1]
            if func == f:
                return int(addr, 16)

        print(
            "[-]No matched, Make sure you supply a valid function name or just add more libc."
        )
        return 0


if __name__ == "__main__":
    obj = LibcSearcher("fgets", 0x7ff39014bd90)
    print("[+]system  offset: ", hex(obj.dump("system")))
    print("[+]/bin/sh offset: ", hex(obj.dump("str_bin_sh")))
