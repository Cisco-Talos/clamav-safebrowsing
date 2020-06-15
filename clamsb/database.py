# Copyright (C) 2019-2020  Cisco Systems, Inc. and/or its affiliates. All rights reserved.
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import *
from sqlalchemy.orm import relationship
from sqlalchemy.types import VARCHAR, TIMESTAMP, FLOAT, CHAR
from sqlalchemy.dialects.mysql import INTEGER

Base = declarative_base()
CURTIME = func.current_timestamp()

""" Threat Lists Syncing Database Objects """
class SBList(Base):
    __tablename__ = 'sbclient_v4_lists'

    id = Column(INTEGER(unsigned=True), nullable=False, autoincrement=True, primary_key=True)
    threatType = Column(VARCHAR(64), nullable=False)
    threatEntryType = Column(VARCHAR(64), nullable=False)
    platformType = Column(VARCHAR(64), nullable=False)
    last_update = Column(TIMESTAMP, nullable=False, server_default=text('%s ON UPDATE %s' % (CURTIME, CURTIME)))
    state = Column(VARCHAR(64), nullable=False)

    prefixes = relationship('SBPrefix', back_populates='reflist', order_by='SBPrefix.prefix')
    hashes = relationship('SBHash', back_populates='reflist', order_by='SBHash.hash')
    updates = relationship('SBLogUpdate', back_populates='reflist', order_by='SBLogUpdate.timestamp')
    __table_args__ = (UniqueConstraint('threatType', 'threatEntryType', 'platformType', name='_feed'),)

class SBPrefix(Base):
    __tablename__ = 'sbclient_v4_prefixes'

    prefix = Column(CHAR(64), nullable=False, primary_key=True)
    reflist_id = Column(INTEGER(unsigned=True), ForeignKey('sbclient_v4_lists.id'), primary_key=True)

    reflist = relationship('SBList', back_populates='prefixes')
    hashes = relationship('SBHash', order_by='SBHash.hash')
    __table_args__ = (UniqueConstraint('prefix', 'reflist_id', name='_prefix_reflist'),)

class SBHash(Base):
    __tablename__ = 'sbclient_v4_hashes'

    hash = Column(CHAR(64), nullable=False, primary_key=True)
    prefix = Column(CHAR(64))
    reflist_id = Column(INTEGER(unsigned=True), ForeignKey('sbclient_v4_lists.id'), nullable=False, primary_key=True)

    reflist = relationship('SBList', back_populates='hashes')
    __table_args__ = (UniqueConstraint('hash', 'reflist_id', name='_hash_reflist'),
                      ForeignKeyConstraint([prefix, reflist_id], [SBPrefix.prefix, SBPrefix.reflist_id]),)


""" Threat Lists Statistics Database Objects """

class SBLogUpdate(Base):
    __tablename__ = 'sbclient_v4_updates'

    id = Column(INTEGER(unsigned=True), nullable=False, autoincrement=True, primary_key=True)
    timestamp = Column(TIMESTAMP, nullable=False, server_default=CURTIME)
    time_elasped = Column(FLOAT)
    removals = Column(INTEGER(unsigned=True), nullable=False)
    additions = Column(INTEGER(unsigned=True), nullable=False)
    old_state = Column(VARCHAR(64), nullable=False)
    new_state = Column(VARCHAR(64), nullable=False)
    reflist_id = Column(INTEGER(unsigned=True), ForeignKey('sbclient_v4_lists.id'))

    reflist = relationship('SBList', back_populates='updates')

class SBLogBuild(Base):
    __tablename__ = 'sbclient_v4_builds'

    id = Column(INTEGER(unsigned=True), nullable=False, autoincrement=True, primary_key=True)
    timestamp = Column(TIMESTAMP, nullable=False, server_default=CURTIME)
    time_elasped = Column(FLOAT)
    prefix_count = Column(INTEGER(unsigned=True), nullable=False)
    hash_count = Column(INTEGER(unsigned=True), nullable=False)
    phish_count = Column(INTEGER(unsigned=True), nullable=False)
    malware_count = Column(INTEGER(unsigned=True), nullable=False)
    bytes = Column(INTEGER(unsigned=True), nullable=False)


if __name__ == "__main__":
    engine = create_engine('mysql://sbclient:PASSWORDHERE@localhost/sbclient')
    Base.metadata.create_all(engine)
