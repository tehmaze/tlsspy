import datetime
from tlsspy.probe.base import Probe


class Timing(Probe):
    def probe(self, address, certificates):
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
