import datetime
from tlsspy.probe.base import Probe


class Timing(Probe):
    def probe(self, address, certificates):
        '''
        Records the start time of the analysis run.

        Provides the following keys:

        * ``analysis.timing.start`` as ISO time

        Probes that depend on this probe:

        * 980_timing_

        .. _980_timing: probe_980_timing.html
        '''
        return self.merge(dict(
            analysis=dict(timing=dict(start=datetime.datetime.now())),
        ))


PROBES = (
    Timing,
)
