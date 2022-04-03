#!/usr/bin/env python
#
# Paths in sqlite db are relative to positition of db file.
# Ignore list are regexes that are matched to beginning of paths.
#

import os
import re
import argparse
import hashlib
import sqlite3


HASH_BUF_SIZE = 65536
DB_DEFAULT = 'duplicate-db.sqlite'
TABLENAME = 'paths'

IGNORELISTPATH = 'duplicate-ignore'

# Populated on runtime
IGNORELIST = []
DB = None


def file_hash(fpath):
    hash = hashlib.sha1()
    with open(fpath, 'rb') as f:
        while True:
            data = f.read(HASH_BUF_SIZE)
            if not data:
                break
            hash.update(data)
    return hash.hexdigest()


def open_or_create_db(dbpath=DB_DEFAULT):
    global DB
    DB = sqlite3.connect(dbpath)
    c = DB.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tablenames = [v[0] for v in c.fetchall()]
    assert len(tablenames) <= 1
    if len(tablenames) == 1 and tablenames[0] != 'paths':
        raise Exception("SQLite db contains foreign tables:", tablenames)
    if len(tablenames) == 0:
        print("Setting up new database.")
        DB.execute("PRAGMA case_sensitive_like = true")
        DB.execute(f"CREATE TABLE {TABLENAME}(path TEXT PRIMARY KEY NOT NULL,"
                   f"hash TEXT NOT NULL, lastmod REAL, dir TEXT NOT NULL)")
        DB.execute(f"CREATE INDEX hashidx ON {TABLENAME}(hash)")
    DB.commit()


def db_update_file(fpath, hash, lastmod, dir=None):
    if dir is None:
        dir = os.path.split(fpath)[0]
    DB.execute(f"INSERT OR REPLACE INTO {TABLENAME} VALUES (?, ?, ?, ?)",
               [fpath, hash, lastmod, dir])


def db_remove_file(fpath):
    DB.execute(f"DELETE FROM {TABLENAME} WHERE path = ?", [fpath])


def db_find_file(fpath):
    c = DB.execute(f"SELECT hash, lastmod FROM {TABLENAME} WHERE path = ?",
                   [fpath])
    row = c.fetchone()
    if row is None:
        raise KeyError
    else:
        return row[0], row[1]


def db_all_subfiles(directory):
    if directory.endswith('/'):
        directory = directory[:-1]
    try:
        return set([db_find_file(directory)[0]])
    except KeyError:
        c = DB.execute(f"SELECT path FROM {TABLENAME}"
                       f" WHERE dir = ? OR dir LIKE ?",
                       [directory, directory+'/%'])
        return set(r[0] for r in c.fetchall())


def db_find_duplicates(hash, fpath=None, source=None):
    """Return entries in database with same hash, that have a
    different path than fpath and begin with source.
    """
    stmt = f"SELECT path, lastmod FROM {TABLENAME} WHERE hash == ?"
    if fpath is not None:
        stmt += " AND path != ?"
    if source is not None:
        stmt += " AND (dir = ? OR dir LIKE ?)"
    stmt += " ORDER BY path"
    c = DB.execute(stmt, [hash] + ([fpath] if fpath is not None else [])
                   + ([source, source+'/%'] if source is not None else []))
    return c.fetchall()


# dir path without trailing slash
def db_dir_list(dirpath):
    c = DB.execute(
        f"SELECT path, hash, lastmod FROM {TABLENAME} "
        f"WHERE dir = ?", [dirpath])
    rows = c.fetchall()
    return rows


def db_commit():
    DB.commit()


def load_ignore(path=IGNORELISTPATH):
    global IGNORELIST
    if not os.path.exists(path):
        return
    print(f"Loading ignore list from {path}")
    with open(path, 'r') as f:
        IGNORELIST = [re.compile(line) for line in f.readlines()
                      if len(line.strip()) > 0]


def is_ignored(fpath):
    return any(regex.match(fpath) for regex in IGNORELIST)


def walk(root, filecb=None, dircb=None):
    for dirpath, dirnames, filenames in os.walk(root):
        if dircb is not None and not is_ignored(dirpath):
            dircb(dirpath, dirnames, filenames)
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            if is_ignored(fpath):
                continue
            if filecb is not None:
                filecb(fpath)


def path_is_in_root(path):
    rp = os.path.realpath(path)
    cur = os.path.realpath('')
    return rp == cur or rp.startswith(cur + os.sep)


def normalize_path(path):
    relpath = os.path.relpath(path)
    return '' if relpath == '.' else relpath


def cmd_hash(cmd, directory, force, delete, simulate):
    if directory is None:
        directory = ''
    else:
        assert path_is_in_root(directory)
        directory = normalize_path(directory)

    if delete:
        oldfiles = db_all_subfiles(directory)

    summary = [0, 0, 0, 0, 0]

    # symbols
    # ✓     in DB and mtime up to date
    #  u    in DB but old mtime
    #   #   hashing and inserting / updating DB
    #    r  deleting from DB
    def filecb(fpath):
        oldfiles.discard(fpath)
        mtime = os.path.getmtime(fpath)
        try:
            dbhash, dbmtime = db_find_file(fpath)
            print(('✓ ' if mtime <= dbmtime else ' u')
                  + ('#' if mtime > dbmtime or force else ' ')
                  + f"   {fpath}")
            if mtime > dbmtime:
                hash = file_hash(fpath)
                if not simulate:
                    db_update_file(fpath, hash, mtime)
            elif force:
                hash = file_hash(fpath)
                if hash != dbhash:
                    if not simulate:
                        db_update_file(fpath, hash, mtime)
                    summary[4] += 1
            if mtime <= dbmtime:
                summary[0] += 1
            else:
                summary[1] += 1
        except KeyError:
            print(f"  #   {fpath}")
            if not simulate:
                db_update_file(
                    fpath, file_hash(fpath), mtime)
            summary[2] += 1

    walk(directory, filecb)

    for fpath in oldfiles:
        db_remove_file(fpath)

    db_commit()
    print(f"{summary[0]} up to date")
    print(f"{summary[1]} updated")
    print(f"{summary[2]} new")
    print(f"{len(oldfiles)} removed")
    if force:
        print(f"FORCE: {summary[4]} of updated files had old time stamps.")


def cmd_duplicates(cmd, directory, source, mark, plain):
    if source is None:
        source = ''
    else:
        if not path_is_in_root(source):
            raise Exception("--source directory not in DB root")
        source = normalize_path(source)

    if directory is None:
        directory = ''
    else:
        directory = normalize_path(directory)

    summary = [0, 0, 0]

    def filecb(fpath):
        summary[0] += 1
        if path_is_in_root(fpath):
            fpath = normalize_path(fpath)

        try:
            hash, mtime = db_find_file(fpath)
            if os.path.getmtime(fpath) >= mtime:
                hash = file_hash(fpath)
        except KeyError:
            hash = file_hash(fpath)

        dup = db_find_duplicates(hash, fpath, source)
        if dup:
            summary[1] += 1
            if plain:
                print(fpath)
            else:
                print(f"{len(dup)} duplicates of {fpath}")
                for fp, mt in dup:
                    print(" -  "+fp)

            if mark:
                dir, name = os.path.split(fpath)
                newpath = os.path.join(dir, mark + name)
                try:
                    os.rename(fpath, newpath)
                    if not plain:
                        print(f" >  Marking {fpath}")
                    hash, mtime = db_find_file(fpath)
                    db_remove_file(fpath)
                    db_update_file(newpath, hash, mtime, dir)
                except OSError:
                    summary[2] += 1
                    print(f"!   Cannot rename {fpath} "
                          f"because {newpath} already exists.")
                except KeyError:
                    pass

    walk(directory, filecb)
    db_commit()
    if not plain:
        print(f"{summary[0]} files total")
        print(f"{summary[1]} are have duplicates")
        if mark:
            print(f"{summary[2]} could not be renamed because"
                  " name already existed")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='cmd', required=True)
    phash = subparsers.add_parser("hash", help="Calculate and store hashes.")
    phash.add_argument("directory", nargs='?')
    phash.add_argument(
        '-f', dest="force", action='store_true',
        help="Force recalculation even on up to date modification times.")
    phash.add_argument(
        '-d', dest="delete", action='store_true',
        help="Delete non-existent paths from database.")
    phash.add_argument(
        '-s', dest='simulate', action='store_true',
        help="Don't change database.")
    pdup = subparsers.add_parser("duplicates", help="Find duplicate files.")
    pdup.add_argument(
        'directory', nargs='?',
        help="Directory to look for duplicates in.")
    pdup.add_argument(
        '--source', dest='source', metavar="DIR",
        help="Only consider this directory as reference,"
             " instead of full database.")
    pdup.add_argument(
        '-m', dest='mark', metavar="STR",
        help="Mark duplicates by prepending string.")
    pdup.add_argument(
        '-p', dest='plain', action='store_true',
        help="Plain output of new line separated file paths with"
        " duplicates only.")
    pforget = subparsers.add_parser(
        "forget", help="Remove files from database.")
    pforget.add_argument(
        'directory', help="File or directory to forget.")
    args = parser.parse_args()

    open_or_create_db()
    load_ignore()

    if args.cmd == 'hash':
        cmd_hash(**vars(args))
    elif args.cmd == 'duplicates':
        cmd_duplicates(**vars(args))
    else:
        raise NotImplementedError
