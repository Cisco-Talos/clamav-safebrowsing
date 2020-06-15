#!/usr/bin/env python
# Copyright (C) 2019-2020  Cisco Systems, Inc. and/or its affiliates. All rights reserved.
import logging
import os
import time
import hashlib
import binascii

from base64 import b64decode
from sqlalchemy import create_engine, exists
from sqlalchemy.orm import sessionmaker

from clamsb import database as db, googleapi
from clamsb.utils import Timer
from clamsbwrite import GDBWriter

DEFAULT_SAFEBROWSING_FEEDS = [
    db.SBList(
        threatType = "MALWARE",
        platformType = "ALL_PLATFORMS",
        threatEntryType = "URL",
        state = "",
    ),
    db.SBList(
        threatType = "SOCIAL_ENGINEERING",
        platformType = "ALL_PLATFORMS",
        threatEntryType = "URL",
        state = "",
    ),
]

class UpdateClient:
    FHLIMIT = 500
    QLIMIT = 100000

    def __init__(self, apikey, db_host, db_user, db_pw, db_name):
        self.log = logging.getLogger(self.__class__.__name__)
        self.apikey = apikey
        self.engine = create_engine('mysql://{}:{}@{}/{}'.format(db_user, db_pw, db_host, db_name))
        db.Base.metadata.create_all(self.engine)
        self.sessionmaker = sessionmaker(bind=self.engine)

        self.gapi = googleapi.GoogleAPI(
            apikey=self.apikey,
        )

    def _log_and_raise(self, message, ErrType=RuntimeError):
        self.log.error(message)
        raise ErrType(message)

    # TODO: detect if there is valid data or invalid parsing data type
    def _extract_ar_entries(self, ar_list):
        ar_entry = {
            'prefixes': [],
            'indices': [],
            'total_count': 0,
        }
        for ar in ar_list:
            if ar['compressionType'] != "RAW":
                self._log_and_raise("invalid compression type for additions/removals list")
            if 'riceHashes' in ar.keys():
                self._log_and_raise("unhandled additions/removals list data class: riceHashes")

            if 'rawHashes' in ar.keys():
                prefix_raw = b64decode(ar['rawHashes']['rawHashes'])
                prefix_size = ar['rawHashes']['prefixSize']
                if prefix_size < 4:
                    self._log_and_raise("invalid prefix size for additions/removals list: {}".format(prefix_size))
                if prefix_size != 4:
                    self.log.warning("prefix size of rawHashes is {} (not 4)".format(prefix_size))
                if len(prefix_raw) % prefix_size:
                    self._log_and_raise("length of rawHashes is not divisable by prefix_length")

                local_prefixes = [ prefix_raw[i:i+prefix_size] for i in range(0, len(prefix_raw), prefix_size) ]
                ar_entry['prefixes'] += local_prefixes

            if 'rawIndices' in ar.keys():
                ar_entry['indices'] += ar['rawIndices']['indices']
            ar_entry['total_count'] += len(ar_entry['prefixes']) + len(ar_entry['indices'])
        return ar_entry

    def _retrieve_updates(self, listobjs):
        gapi_resp = self.gapi.get_threats_update(listobjs)
        updates = {}
        for up in gapi_resp:
            entry = {
                'responseType':  up['responseType'],
                'threatType':    up['threatType'],
                'threatEntryType': up['threatEntryType'],
                'platformType':    up['platformType'],
                'newClientState':  up['newClientState'],
                'checksum':        b64decode(up['checksum']['sha256']), #sha256 of all hashes
            }
            if 'removals' in up:
                entry['removals'] = self._extract_ar_entries(up['removals'])
            if 'additions' in up:
                entry['additions'] = self._extract_ar_entries(up['additions'])
            listobj_ref = "{}.{}.{}".format(up['threatType'], up['threatEntryType'], up['platformType'])
            updates[listobj_ref] = entry
        return updates

    def _retrieve_fullhashes(self, listobjs, prefix_set):
        # ignoring the cache duration
        gapi_resp = self.gapi.get_full_hashes(listobjs, prefix_set)
        hashes = []
        for m in gapi_resp:
            hashes.append(b64decode(m['threat']['hash']))
        return hashes

    def _validate_checksum(self, session, listobj, checksum):
        listobj_ref = "{}.{}.{}".format(listobj.threatType, listobj.threatEntryType, listobj.platformType,)
        item_count = session.query(db.SBPrefix.reflist_id)\
                            .filter(db.SBPrefix.reflist_id == listobj.id)\
                            .count()

        calc = hashlib.sha256()
        items = 0
        while items < item_count:
            job_size = min(self.QLIMIT, item_count-items)
            prefixobjs = session.query(db.SBPrefix)\
                                .filter(db.SBPrefix.reflist_id == listobj.id)\
                                .order_by(db.SBPrefix.prefix)\
                                .slice(items, items+job_size).all()
            items += job_size

            for h in prefixobjs:
                calc.update(binascii.unhexlify(h.prefix))
        self.log.info("computed checksum of prefixes for {} = {}".format(listobj_ref, calc.hexdigest()))
        if calc.digest() != checksum:
            self.log.error("computed checksum does not match expected checksum: {} =/= {}"\
                           .format(calc.hexdigest(), binascii.hexlify(checksum)))
            return False
        else:
            self.log.info("computed checksum of prefixes matches expected checksum")
        return True

    def Valid(self, lists=None, updates=None, full=False):
        validity = True
        session = self.sessionmaker()
        if lists:
            listobjs = []
            for l in lists:
                listobj = session.query(db.SBList)\
                                 .filter(db.SBList.threatType == l.get('threatType'))\
                                 .filter(db.SBList.threatEntryType == l.get('threatEntryType'))\
                                 .filter(db.SBList.platformType == l.get('platformType'))\
                                 .one()
                listobjs.append(listobj)
        else:
            listobjs = session.query(db.SBList).all()
        if not listobjs:
            self.log.info("no existing lists detected for validation")
            return validity

        empty_listobjs = [ feed for feed in listobjs if not feed.state ]
        for listobj in empty_listobjs:
            listobj_ref = "{}.{}.{}".format(listobj.threatType, listobj.threatEntryType, listobj.platformType,)
            p_count = session.query(db.SBPrefix.reflist_id)\
                             .filter(db.SBPrefix.reflist_id == listobj.id)\
                             .count()
            if p_count > 0:
                self.log.error("{} has no previous state but has {} prefixes".format(listobj_ref, p_count))
                if not full:
                    return False
                validity = False
            h_count = session.query(db.SBHash.reflist_id)\
                             .filter(db.SBHash.reflist_id == listobj.id)\
                             .count()
            if h_count > 0:
                self.log.error("{} has no previous state but has {} hashes".format(listobj_ref, h_count))
                if not full:
                    return False
                validity = False

        active_listobjs = [ feed for feed in listobjs if feed.state ]
        if not active_listobjs:
            self.log.info("no active lists require validation")
            return validity

        if not updates:
            updates = self._retrieve_updates(active_listobjs)

        for listobj in active_listobjs:
            listobj_ref = "{}.{}.{}".format(listobj.threatType, listobj.threatEntryType, listobj.platformType,)
            list_update = updates.get(listobj_ref, None)
            if not list_update:
                self.log.warning("no applicable update found for validation of {}".format(listobj_ref))
                continue

            if 'additions' in list_update or 'removals' in list_update:
                self.log.warning("cannot preform prefix checksum validation on {}: not synced".format(listobj_ref))
            elif not self._validate_checksum(session, listobj, list_update['checksum']):
                if not full:
                    return False
                validity = False

            # check if any prefixes are missing hashes; QUERY:
            #   SELECT p FROM SBPrefix AS p
            #   WHERE NOT EXISTS (SELECT h.prefix FROM SBHash AS h WHERE h.prefix=p.prefix);
            #   WHERE p.reflist_id = listobj.id
            dangling_prefixes = session.query(db.SBPrefix)\
                                       .filter(~exists().where(db.SBHash.prefix == db.SBPrefix.prefix))\
                                       .filter(db.SBPrefix.reflist_id == listobj.id)\
                                       .all()
            if not dangling_prefixes:
                self.log.info("{} prefixes all have an attributed hash".format(listobj_ref,))
            else:
                self.log.warning("{} has {} prefixes without an attributed hash".format(listobj_ref, len(dangling_prefixes)))
                for p in dangling_prefixes:
                    self.log.debug("{}".format(p.prefix))
                if not full:
                    return False
                validity = False

        return validity

    """ optional list of dicts referring to list parameters to purge """
    def Purge(self, lists=None):
        session = self.sessionmaker()
        if lists:
            self.log.debug("purging select database state and associated hashes")
            for l in lists:
                listobj_ref = "{}.{}.{}".format(l.get('threatType'), l.get('threatEntryType'), l.get('platformType'),)
                listobj = session.query(db.SBList)\
                                 .filter(db.SBList.threatType == l.get('threatType'))\
                                 .filter(db.SBList.threatEntryType == l.get('threatEntryType'))\
                                 .filter(db.SBList.platformType == l.get('platformType'))\
                                 .one_or_none()
                if not listobj:
                    self.log.warning("cannot purge {}: does not exist".format(listobj_ref))
                    continue

                self.log.debug("purging {} @ {}".format(listobj_ref, listobj.state))
                try:
                    session.query(db.SBHash.reflist_id)\
                           .filter(db.SBHash.reflist_id == listobj.id)\
                           .delete()
                    session.commit()
                except:
                    self.log.error("failed to purge hashes for {} @ {}, rollback".format(listobj_ref, listobj.state))
                    session.rollback()
                    raise
                try:
                    session.query(db.SBPrefix.reflist_id)\
                           .filter(db.SBPrefix.reflist_id == listobj.id)\
                           .delete()
                    session.commit()
                except:
                    self.log.error("failed to purge prefixes for {} @ {}, rollback".format(listobj_ref, listobj.state))
                    session.rollback()
                    raise

                if listobj.state != "":
                    listobj.state = ""
                    session.add(listobj)
                    try:
                        session.commit()
                    except:
                        self.log.error("failed to reset list state for {} @ {}, rollback".format(listobj_ref, listobj.state))
                        session.rollback()
                        raise
        else:
            self.log.debug("purging all database state and hashes")
            try:
                session.query(db.SBHash).delete()
                session.commit()
            except:
                self.log.error("failed to purge database threat list hashes, rollback")
                session.rollback()
                raise
            try:
                session.query(db.SBPrefix).delete()
                session.commit()
            except:
                self.log.error("failed to purge database threat list prefixes, rollback")
                session.rollback()
                raise

            for listobj in session.query(db.SBList).all():
                listobj.state = ""
                session.add(listobj)
            try:
                session.commit()
            except:
                self.log.error("failed to reset database threat list states, rollback")
                session.rollback()
                raise
        self.log.debug("purging database complete")

    def Update(self, lists=None):
        session = self.sessionmaker()
        if lists:
            listobjs = []
            for l in lists:
                listobj_ref = "{}.{}.{}".format(l.get('threatType'), l.get('threatEntryType'), l.get('platformType'),)
                listobj = session.query(db.SBList)\
                                 .filter(db.SBList.threatType == l.get('threatType'))\
                                 .filter(db.SBList.threatEntryType == l.get('threatEntryType'))\
                                 .filter(db.SBList.platformType == l.get('platformType'))\
                                 .one_or_none()
                # if a listobj doesn't exist, make one
                if not listobj:
                    self.log.info("adding {} to database lists".format(listobj_ref))
                    listobj = db.SBList(
                        threatType = l.get('threatType'),
                        threatEntryType = l.get('threatEntryType'),
                        platformType = l.get('platformType'),
                        state = "",
                    )
                    session.add(listobj)
                    try:
                        session.commit()
                    except:
                        self.log.error("failed to add {} to database threat list states, rollback".format(listobj_ref))
                        session.rollback()
                        raise
                listobjs.append(listobj)
        else:
            listobjs = session.query(db.SBList).all()
            if not listobjs:
                self.log.debug("no previous updates were detected, using default")
                listobjs = DEFAULT_SAFEBROWSING_FEEDS
                for feed in listobjs:
                    session.add(feed)
                try:
                    session.commit()
                except:
                    self.log.error("failed to initialize database threat list states, rollback")
                    session.rollback()
                    raise

        for listobj in listobjs:
            self.log.debug("retrieved {}.{}.{} @ {}".format(
                listobj.threatType,
                listobj.threatEntryType,
                listobj.platformType,
                listobj.state if listobj.state else "NEW",
            ))

        return self._retrieve_updates(listobjs)

    def _handle_removals(self, session, listobj, removals):
        listobj_ref = "{}.{}.{}".format(listobj.threatType, listobj.threatEntryType, listobj.platformType,)
        rmcount = 0

        if len(removals['indices']) > 0:
            self.log.debug("processing {} indice removals for {}".format(len(removals['indices']), listobj_ref))
            rm_prefixes = []
            for item in removals['indices']:
                prefixobj = session.query(db.SBPrefix)\
                                   .filter(db.SBPrefix.reflist_id == listobj.id)\
                                   .order_by(db.SBPrefix.prefix)\
                                   .limit(1).offset(item).one()
                rm_prefixes.append(prefixobj)
            # we could do these in place since the changes are not
            # reflected until commit but this is probably much safer
            for p in rm_prefixes:
                for h in p.hashes:
                    self.log.debug("rm {} :: {}".format(p.prefix, h.hash))
                    session.delete(h)
                    rmcount += 1
                self.log.debug("rm {}".format(p.prefix,))
                session.delete(p)
                rmcount += 1

        if len(removals['prefixes']) > 0:
            self.log.debug("processing {} prefix removals for {}".format(len(removals['prefixes']), listobj_ref))
            for item in removals['prefixes']:
                self._log_and_raise("{}: prefixes are unimplemented for handling removals".format(listobj_ref))

                # an idea of how this might work but not necessarily correct, needs to be tested
                prefixobj = session.query(db.SBPrefix)\
                                   .filter(db.SBPrefix.prefix == binascii.hexify(item))\
                                   .one_or_none()
                if not prefixobj:
                    self.log.warning("failed to locate prefix {} in database for removal".format(item,))
                    continue
                for h in prefixobj.hashes:
                    self.log.debug("rm {} :: {}".format(prefix, h.hash))
                    session.delete(h)
                    rmcount += 1
                self.log.debug("rm {}".format(prefix,))
                session.delete(prefixobj)
                rmcount += 1

        self.log.info("removing {} entries from {}".format(rmcount, listobj_ref))

    def _handle_additions(self, session, listobj, additions):
        listobj_ref = "{}.{}.{}".format(listobj.threatType, listobj.threatEntryType, listobj.platformType,)
        addcount = 0

        if len(additions['indices']) > 0:
            self.log.debug("processing {} indice additions for {}".format(len(additions['indices']), listobj_ref))
            for item in additions['indices']:
                self._log_and_raise("{}: indices are unimplemented for handling additions".format(listobj_ref))

        if len(additions['prefixes']) > 0:
            self.log.debug("processing {} prefix additions for {}".format(len(additions['prefixes']), listobj_ref))

            chunkidx = 0; consumed = 0; matches = 0; commit = 0
            prefixes = additions['prefixes']
            for prefixset in [ prefixes[i:i + self.FHLIMIT] for i in range(0, len(prefixes), self.FHLIMIT) ]:
                self.log.debug("handling {} - {} of {}".format(chunkidx, chunkidx+len(prefixset), len(prefixes)))
                chunkidx += len(prefixset)

                prefixobjs_dict = dict()
                prefixused = set()
                for p in prefixset:
                    prefix_str = binascii.hexlify(p)
                    self.log.debug("add {}".format(prefix_str))
                    prefixobjs_dict[p] = prefixobj = db.SBPrefix(
                        prefix = prefix_str,
                        reflist = listobj,
                    )
                    session.merge(prefixobj)
                commit += len(prefixset) # count prefixes
                addcount += len(prefixset)

                hashes = self._retrieve_fullhashes([listobj], prefixset)
                for h in hashes:
                    prefix_matches = [ p for p in prefixset if h.startswith(p) ]
                    if len(prefix_matches) != 1:
                        self._log_and_raise("{}: matched hash does not match exactly one prefix".format(listobj_ref))
                    prefix = prefix_matches[0]
                    prefixused.add(prefix)

                    prefixobj = prefixobjs_dict[prefix]
                    prefix_str = binascii.hexlify(prefix)
                    hash_str = binascii.hexlify(h)
                    self.log.debug("add {} :: {}".format(prefix_str, hash_str))
                    hashobj = db.SBHash(
                        hash = hash_str,
                        prefix = prefix_str, # done this way due to composite foreign key
                        reflist = listobj,
                    )
                    session.merge(hashobj)
                    matches += 1
                    addcount += 1
                    commit += 1 # count hashes

                if len(prefixset) != len(prefixused):
                    self.log.warning("prefix set does not fully match retrieved list: expected {} =/= retrieved {}"\
                                     .format(len(prefixset), len(prefixused)))
                consumed += len(prefixused)

                if commit > self.QLIMIT:
                    self.log.info("commiting additions segment for {}".format(listobj_ref))
                    try:
                        session.commit()
                    except:
                        session.rollback()
                        self.log.error("commiting additions segment for {} failed, rollback".format(listobj_ref))
                        raise
                    commit = 0 # reset for next use
            if len(prefixes) != consumed:
                self.log.debug("mismatch prefix count to matched prefix count: have {} =/= consumed {}"\
                              .format(len(prefixes), consumed))

            self.log.info("adding {} new entries to {}".format(addcount, listobj_ref))

    def Sync(self, lists=None, updates=None):
        if not updates:
            self.log.debug("retrieving threats updates...")
            updates = self.Update(lists=lists)
            self.log.debug("retrieving threats updates success")

        session = self.sessionmaker()
        if lists:
            listobjs = []
            for l in lists:
                listobj = session.query(db.SBList)\
                                 .filter(db.SBList.threatType == l.get('threatType'))\
                                 .filter(db.SBList.threatEntryType == l.get('threatEntryType'))\
                                 .filter(db.SBList.platformType == l.get('platformType'))\
                                 .one()
                listobjs.append(listobj)
        else:
            listobjs = session.query(db.SBList).all()
        if not listobjs:
            self.log.error("no specified or detected lists to sync")
            return
        session.close()

        """
        # quick count summary
        rm_count = 0; add_count = 0
        for up in updates:
            up_rm_count = 0; up_add_count = 0
            if 'removals' in up:
                up_rm_count += up['removals']['total_count']
            if 'additions' in up:
                up_add_count += up['additions']['total_count']
            self.log.debug("{} removals and {} additions for {}.{}.{}".format(
                up_rm_count, up_add_count, up['responseType'], up['threatType'], up['threatEntryType']))
            rm_count += up_rm_count
            add_count += up_add_count
        self.log.info("retrieved total [ {} removals, {} additions ]".format(rm_count, add_count))
        """

        t = Timer("db.update")
        for listobj in listobjs:
            t.start()
            listobj_ref = "{}.{}.{}".format(listobj.threatType, listobj.threatEntryType, listobj.platformType,)
            list_update = updates.get(listobj_ref, None)
            if not list_update:
                self.log.warning("no applicable update found for sync of {}".format(listobj_ref))
                continue

            self.log.info("processing changes for {} from {} to {}".format(
                listobj_ref,
                listobj.state if listobj.state else "NEW",
                list_update.get('newClientState')
            ))
            session = self.sessionmaker()
            if 'removals' in list_update:
                self._handle_removals(session, listobj, list_update['removals'])
            if 'additions' in list_update:
                self._handle_additions(session, listobj, list_update['additions'])
            self.log.info("updating state for {} from {} to {}".format(
                listobj_ref,
                listobj.state if listobj.state else "NEW",
                list_update.get('newClientState')
            ))

            listobj_oldstate = listobj.state
            listobj.state = list_update['newClientState']
            session.merge(listobj)
            try:
                session.commit()
            except:
                session.rollback()
                self.log.error("syncing update to {} for {} failed, rollback".format(
                    listobj.state,
                    listobj_ref,
                ))
                raise

            t.stop()
            self.log.info("sync success for {} - {}".format(listobj_ref, t.human_readable))
            update_summary = db.SBLogUpdate(
                time_elasped = t.time(),
                removals = list_update['removals']['total_count'] if 'removals' in list_update else 0,
                additions = list_update['additions']['total_count'] if 'additions' in list_update else 0,
                old_state = listobj_oldstate,
                new_state = listobj.state,
                reflist = listobj,
            )
            session.add(update_summary)
            try:
                session.commit()
            except:
                self.log.error("failed to write update log for {} to database, rollback".format(listobj_ref))
                session.rollback()

            # validate checksum and output to log but don't perform an action based on outcome
            self._validate_checksum(session, listobj, list_update['checksum'])

        self.log.debug("Sync Complete")


if __name__ == "__main__":
    import argparse
    import sys
    import datetime
    import apacheconfig
    import clamsb.utils as utils

    cli_parser = argparse.ArgumentParser()
    cli_parser.add_argument(
        "--config", "-C", dest="configfile", action="store",
        help="specify an alternate config file (default: %(default)s",
        default=os.path.join("/etc", "clamav", "safebrowsing.conf"))
    # default in prior version was to simply log to /tmp/sb.log
    # at DEBUG level
    cli_parser.add_argument("-d", "--debug",
                            dest="debug", action="store_true", help=argparse.SUPPRESS)
    cli_parser.add_argument("-v", "--verbose", dest = "verbose",
                            action="store_true", help="be verbose")
    cli_parser.add_argument("--logfile",
                            dest="logfile", action="store", nargs="?",
                            help="Specify a logfile destination")
    cli_parser.add_argument("command", action="store", nargs="?", default="build",
                            help="Command to run on database: [build(*), sync, validate, dump, load, purge]")
    progname = os.path.basename(sys.argv[0])
    opts = cli_parser.parse_args(sys.argv[1:])
    log = utils.setup_logging(opts.debug, opts.verbose, logfile=opts.logfile)
    log.info("Running update.py CLI")

    with apacheconfig.make_loader() as loader:
        config = loader.load(opts.configfile)['safebrowsing']
        apikey, db_host, db_user, db_pw, db_name, outputdir = [
            config.get(key) for key in ["apikey", "db_host", "db_user", "db_pw", "db_name", "outputdir"]
        ]

    client = UpdateClient(apikey, db_host, db_user, db_pw, db_name)

    command = opts.command.lower()
    if command in ["build", "b"]:
        client.Sync()
        g = GDBWriter(db_host, db_user, db_pw, db_name)
        outpath = os.path.join(outputdir, "safebrowsing-%d.gdb" % int((time.time())))
        g.writegdb(outpath)
    elif command in ["sync", "s"]:
        client.Sync()
    elif command in ["validate", "v"]:
        if client.Valid():
            print("OK")
        else:
            print("possible desync")
    elif command in ["dump", "d"]:
        import pickle
        updates = client.Update()
        pickle.dump(updates, open('updates.p', 'wb'))
    elif command in ["load", "l"]:
        import pickle
        updates = pickle.load(open('updates.p', 'rb'))
        client.Sync(updates)
    elif command in ["purge"]:
        client.Purge()
    else:
        print("unknown command: {}".format(command))
