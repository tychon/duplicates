Tool to find duplicate files by comparing hashes.  Use for example to
clean up mixed up piles of backups of backups of pictures on your
family's hard drives...

As a first step index file hashes in a directory.

    python duplicates.py hash DIRECTORY

By default a database for hashes is created in the working directory.
Paths given to this command have to be in the same directory or its
children, because relative paths are used in the database.

To find duplicates use

    python duplicates.py duplicates DIRECTORY

This will list all files which have duplicates by hash value indexed
in the database.

There are more options available.  Check with `-h` flag.  It is
possible to create an ignore list given as regular expression in a
file `duplicate-ignore` in the working directory.

Tip: With flag `-p` (plain) to `duplicates` command, you can use
`xargs` to for example remove duplicates:

    python duplicates.py duplicates --source SRCDIR -p DIR | xargs rm -v --
