#!/usr/bin/env python
#
# Copyright (c) 2015 Catalyst.net Ltd
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""
Produce an sqlite database of sniffed DNS qnames grouped by hour.

Michael Fincham <michael.fincham@catalyst.net.nz>
"""

import argparse
import datetime
import logging
import sys
import sqlite3

from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.l2 import Ether

from raw import DnsSniffer

class AnswerCounter(object):
    DEFAULT_DATABASE_PATH = 'survey.sqlite3'
    DEFAULT_PACKET_COUNT_INTERVAL = 100

    def __init__(self, database_path=DEFAULT_DATABASE_PATH, packet_count_interval=DEFAULT_PACKET_COUNT_INTERVAL):
        self.database_path = database_path
        self.packet_count_interval = packet_count_interval
        self.totals = {}
        self.packet_count = 0
        logging.info('using database "%s"' % self.database_path)

        try:
            self.conn = sqlite3.connect(self.database_path)
            self.conn.execute(
                "create table if not exists qnames(qname TEXT, qtype TEXT, hour INTEGER, count INTEGER, UNIQUE(qname, qtype, hour));"
            )
        except:
            logging.error('unable to open database "%s"' % self.database_path)
            raise

    def _hour(self):
        return datetime.datetime.now().replace(minute=0, second=0, microsecond=0)

    def _sniffer_callback(self, packet):
        import pdb; pdb.set_trace()
        if packet.haslayer(DNSRR) and packet.haslayer(DNSQR) and packet[DNS].aa == 1 and packet[DNS].rcode == 0:
            qname = packet[DNSQR].qname.lower()
            qtype = packet[DNSQR].sprintf("%qtype%")

            if (qname, qtype) not in self.totals:
                self.totals[(qname, qtype)] = 0

            self.totals[(qname, qtype)] += 1
            self.packet_count += 1

        if self.packet_count == 1000:
            logging.info('saving totals to database...')

            try:
                c = self.conn.cursor()

                for qr, count in self.totals.iteritems():
                    qname = qr[0]
                    qtype = qr[1]
                    hour = self._hour()
                    c.execute("INSERT OR IGNORE INTO qnames VALUES (?, ?, ?, 0);", (qname, qtype, hour))
                    c.execute("UPDATE qnames SET count = count + ? WHERE qname=? AND qtype=? AND hour=?;", (count, qname, qtype, hour))

                self.conn.commit()
                self.packet_count = 0
                self.totals = {}
                logging.info('saved')
            except:
                logging.error('could not save to database')
                raise

    def start_capture(self):
        logging.info('starting sniffer...')

        try:
            sniffer = DnsSniffer()
            for packet in sniffer.sniff():
                self._sniffer_callback(Ether(packet))
        except:
            logging.error('could not capture packets')
            raise

if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s %(message)s', level=logging.INFO)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database-path', metavar="PATH", type=str, default=AnswerCounter.DEFAULT_DATABASE_PATH, help='path to sqlite3 database for output, defaults to %s' % AnswerCounter.DEFAULT_DATABASE_PATH)
    parser.add_argument('--packet-count-interval', metavar="PACKETS", type=int, default=AnswerCounter.DEFAULT_PACKET_COUNT_INTERVAL, help='how many packets between database flushes, defaults to %i' % AnswerCounter.DEFAULT_PACKET_COUNT_INTERVAL)
    args = parser.parse_args()

    try:
        counter = AnswerCounter(database_path=args.database_path, packet_count_interval=args.packet_count_interval)
        counter.start_capture()
    except:
        logging.error('error encountered during capture, giving up')
        sys.exit(1)
