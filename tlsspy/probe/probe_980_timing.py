import datetime
from tlsspy.probe.base import Probe


class Timing(Probe):
    def probe(self, address, certificates):
        '''
        Records the end time and run time of the analysis run.

        Provides the following keys:

        * ``analysis.timing.finish`` as ISO time
        * ``analysis.timing.runtime``
        '''
        finish = datetime.datetime.now()
        runtime = finish - self.collected['analysis']['timing']['start']
        return self.merge(dict(
            analysis=dict(timing=dict(
                finish=finish,
                runtime=runtime,
            )),
        ))


PROBES = (
    Timing,
)
