#!/usr/bin/env python
# Copyright (C) 2019-2020  Cisco Systems, Inc. and/or its affiliates. All rights reserved.
import logging
import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from clamsb import database as db
from clamsb.utils import Timer

class GDBWriter(object):
    QLIMIT = 100000
    PREFIX_LEN = 4

    def __init__(self, host, user, pw, dbname):
        self.log = logging.getLogger(self.__class__.__name__)

        self.engine = create_engine('mysql://{}:{}@{}/{}'.format(user, pw, host, dbname))
        self.sessionmaker = sessionmaker(bind=self.engine)

    def writegdb(self, filename):
        f = open(filename,'w')
        self.log.info('Building GDB, writing to {}'.format(filename))

        prefixprinted = set()
        count_phish = 0
        count_malware = 0
        count_prefixes = 0
        items = 0

        t = Timer("db.build")
        t.start()

        session = self.sessionmaker()
        lists = session.query(db.SBList).all()
        prefix_lns = []
        for feed in lists:
            listobj_ref = "{}.{}.{}".format(feed.threatType, feed.threatEntryType, feed.platformType)
            if feed.threatType == "SOCIAL_ENGINEERING":
                pfx = "S"
            elif feed.threatType == "MALWARE":
                pfx = "S2"
            else:
                self.log.info("Ignoring {} @ {}".format(listobj_ref, feed.state))
                continue

            self.log.info("Processing {} @ {}".format(listobj_ref, feed.state))

            hash_count = session.query(db.SBHash.reflist_id)\
                                .filter(db.SBHash.reflist_id == feed.id)\
                                .count()
            self.log.info("Identified {} hashes".format(hash_count))

            items = 0
            while items < hash_count:
                job_size = min(self.QLIMIT, hash_count-items)
                feed_hashes = session.query(db.SBHash)\
                              .filter(db.SBHash.reflist_id == feed.id)\
                              .order_by(db.SBHash.hash)\
                              .slice(items, items+job_size).all()
                self.log.debug("Processing {} - {}".format(items, items+job_size))
                items += job_size

                for item in feed_hashes:
                    prefix_gdb = item.hash[0:2*self.PREFIX_LEN]
                    if prefix_gdb and prefix_gdb not in prefixprinted:
                        prefixprinted.add(prefix_gdb)
                        prefix_lns.append(pfx+":P:"+prefix_gdb+"\n")
                        count_prefixes += 1
                    if item.hash:
                        f.write(pfx+":F:"+item.hash+"\n")
                        if feed.threatType == "SOCIAL_ENGINEERING":
                            count_phish += 1
                        elif feed.threatType == "MALWARE":
                            count_malware += 1
            self.log.info("Processed {}.{}.{}: {}".format(
                feed.threatType, feed.threatEntryType, feed.platformType, str(t)))
        # sorting by type speeds up clamav scan by factor of 10
        for pln in prefix_lns:
            f.write(pln)

        count_bytes = f.tell()
        f.close()

        t.stop()
        build_summary = db.SBLogBuild(
            time_elasped = t.time(),
            prefix_count = count_prefixes,
            hash_count = count_phish+count_malware,
            phish_count = count_phish,
            malware_count = count_malware,
            bytes = count_bytes,
        )
        session.add(build_summary)
        try:
            session.commit()
        except:
            self.log.error("Failed to write build log to database, rollback")
            session.rollback()

        self.log.info("Building GDB complete - {} bytes".format(count_bytes))
        self.log.info("Processed {} lines from {} items".format(
            count_prefixes+count_phish+count_malware, items))
        self.log.info("Counted {} prefixes, {} phish, {} malware".format(
             count_prefixes, count_phish, count_malware))


if __name__ == "__main__":
    import os
    import argparse
    import apacheconfig
    import clamsb.utils as utils

    cli_parser = argparse.ArgumentParser()
    cli_parser.add_argument("--config", "-C", dest = "configfile",
                            action="store",
                            help="specify an alternate config file (default: %(default)s",
                            default=os.path.join("/etc", "clamav", "safebrowsing.conf"))
    cli_parser.add_argument("-d", "--debug", dest = "debug",
                            action="store_true", help=argparse.SUPPRESS)
    cli_parser.add_argument("-v", "--verbose", dest = "verbose",
                            action="store_true", help="be verbose")
    cli_parser.add_argument("--logfile",
                            dest="logfile", action="store", nargs="?",
                            help="Specify a logfile destination")
    opts = cli_parser.parse_args(sys.argv[1:])

    log = utils.setup_logging(opts.debug, opts.verbose, logfile=opts.logfile)
    log.info("Running gdbwrite.py CLI")

    with apacheconfig.make_loader() as loader:
        config = loader.load(opts.configfile)['safebrowsing']
        db_host, db_user, db_pw, db_name, outputdir = [
            config.get(key) for key in ["db_host", "db_user", "db_pw", "db_name", "outputdir"]
        ]

    g = GDBWriter(db_host, db_user, db_pw, db_name)
    outpath = os.path.join(outputdir, "safebrowsing.gdb")
    g.writegdb(outpath)
