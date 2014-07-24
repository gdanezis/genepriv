# Copyright (c) 2014, George Danezis (University College London) All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import time

class custom_protocol:
    def __init__(self, enter, exit):
        self.enter = enter
        self.exit = exit

    def __enter__(self):
        return self.enter(self)

    def __exit__(self, *a):
        return self.exit(*a)


class StatKeeper:
    def __init__(self):
        self.log = {}
        self.starts = {}
        self.order = []

        ## Self test
        for x in range(10000):
            with(self["overhead"]):
                pass

    def __getitem__(self, key):
        def myenter(x):
            self.start(key)
            return None

        def myexit(*a):
            return self.end(key)

        return custom_protocol(myenter, myexit)

    def start(self, action):
        assert action not in self.starts
        self.starts[action] = time.clock()

    def end(self, action):
        assert action in self.starts
        Dt = time.clock() - self.starts[action]
        if action not in self.log:
            self.order += [action]
        count, period = self.log.get(action, (0, 0.0))
        count += 1
        period += Dt
        self.log[action] = (count, period)
        del self.starts[action]

    def get_stats(self):
        assert len(self.starts) == 0
        return self.log

    def print_stats(self):
        ovcnt, ovtime = self.log["overhead"]
        overhead = 1000 * ovtime / ovcnt
        print "Statistics: Counts and Timings"
        print " "*20 + "\tCounter \tTotal   \tAverage"
        for k in self.order:
            cnt, tot = self.log[k]
            xtot = max(1000*tot - cnt*overhead, 0.0)
            xave = max(1000*tot/cnt - overhead, 0.0)
            print "%20s\t%8d\t%8.6f\t%8.6f" % (k, cnt, xtot, xave)
        print "\t\t\t\t\t\t(All times in miliseconds)"
