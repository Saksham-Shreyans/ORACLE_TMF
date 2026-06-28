from __future__ import annotations
import logging
import math
import random
import time
from dataclasses import dataclass,field
from typing import Iterator,Optional
from config.stage2_settings import(
    OU_ACCEL_MU,
    OU_DT,
    OU_GYRO_MU,
    OU_LIGHT_MU,
    OU_SIGMA,
    OU_THETA,
)
logger=logging.getLogger(__name__)
@dataclass
class SensorSample:
    timestamp_ns:int=0
    gyro_x:float=0.0
    gyro_y:float=0.0
    gyro_z:float=0.0
    accel_x:float=0.0
    accel_y:float=0.0
    accel_z:float=9.81
    light:float=250.0
    proximity:float=5.0
@dataclass
class OUProcess:
    mu:float=0.0
    theta:float=OU_THETA
    sigma:float=OU_SIGMA
    dt:float=OU_DT
    seed:Optional[int]=None
    _state:float=field(init=False,repr=False,default=0.0)
    _rng:object=field(init=False,repr=False,default=None)
    def __post_init__(self)->None:
        self._state=self.mu
        self._rng=random.Random(self.seed)
    def step(self)->float:
        drift=self.theta*(self.mu-self._state)*self.dt
        diffusion=self.sigma*math.sqrt(self.dt)*self._rng.gauss(0,1)
        self._state+=drift+diffusion
        return self._state
    def reset(self)->None:
        self._state=self.mu
class SensoryEmulator:
    def __init__(self,seed:Optional[int]=None)->None:
        self._gyro_x=OUProcess(mu=OU_GYRO_MU,theta=OU_THETA,sigma=OU_SIGMA,dt=OU_DT,seed=seed)
        self._gyro_y=OUProcess(mu=OU_GYRO_MU,theta=OU_THETA,sigma=OU_SIGMA,dt=OU_DT,seed=(seed or 0)+1)
        self._gyro_z=OUProcess(mu=OU_GYRO_MU,theta=OU_THETA*0.5,sigma=OU_SIGMA*0.7,dt=OU_DT,seed=(seed or 0)+2)
        self._accel_x=OUProcess(mu=0.0,theta=OU_THETA,sigma=OU_SIGMA*2,dt=OU_DT,seed=(seed or 0)+3)
        self._accel_y=OUProcess(mu=0.0,theta=OU_THETA,sigma=OU_SIGMA*2,dt=OU_DT,seed=(seed or 0)+4)
        self._accel_z=OUProcess(mu=OU_ACCEL_MU,theta=OU_THETA*2,sigma=OU_SIGMA,dt=OU_DT,seed=(seed or 0)+5)
        self._light=OUProcess(mu=OU_LIGHT_MU,theta=0.1,sigma=5.0,dt=1.0,seed=(seed or 0)+6)
        self._t0_ns=time.time_ns()
        self._tick=0
        logger.info("[SensoryEmulation] OU emulator initialised (seed=%s)",seed)
    def next_sample(self)->SensorSample:
        self._tick+=1
        timestamp_ns=self._t0_ns+int(self._tick*OU_DT*1e9)
        return SensorSample(
            timestamp_ns=timestamp_ns,
            gyro_x=round(self._gyro_x.step(),6),
            gyro_y=round(self._gyro_y.step(),6),
            gyro_z=round(self._gyro_z.step(),6),
            accel_x=round(self._accel_x.step(),6),
            accel_y=round(self._accel_y.step(),6),
            accel_z=round(self._accel_z.step(),6),
            light=round(max(0.0,self._light.step()),2),
            proximity=5.0,
        )
    def generate_stream(self,n_samples:int)->Iterator[SensorSample]:
        for _ in range(n_samples):
            yield self.next_sample()
    def sample_as_android_json(self,sample:SensorSample)->dict:
        return{
            "TYPE_GYROSCOPE":{
                "timestamp":sample.timestamp_ns,
                "values":[sample.gyro_x,sample.gyro_y,sample.gyro_z],
                "accuracy":3,
            },
            "TYPE_ACCELEROMETER":{
                "timestamp":sample.timestamp_ns,
                "values":[sample.accel_x,sample.accel_y,sample.accel_z],
                "accuracy":3,
            },
            "TYPE_LIGHT":{
                "timestamp":sample.timestamp_ns,
                "values":[sample.light],
                "accuracy":3,
            },
            "TYPE_PROXIMITY":{
                "timestamp":sample.timestamp_ns,
                "values":[sample.proximity],
                "accuracy":3,
            },
        }
    def compute_variance_report(self,n_samples:int=300)->dict:
        samples=list(self.generate_stream(n_samples))
        def _stats(values:list[float])->dict:
            n=len(values)
            mean=sum(values)/n
            variance=sum((v-mean)**2 for v in values)/n
            return{
                "mean":round(mean,6),
                "variance":round(variance,8),
                "std":round(math.sqrt(variance),6),
                "samples":n,
            }
        return{
            "gyro_x":_stats([s.gyro_x for s in samples]),
            "gyro_y":_stats([s.gyro_y for s in samples]),
            "gyro_z":_stats([s.gyro_z for s in samples]),
            "accel_x":_stats([s.accel_x for s in samples]),
            "accel_y":_stats([s.accel_y for s in samples]),
            "accel_z":_stats([s.accel_z for s in samples]),
            "light":_stats([s.light for s in samples]),
        }
    def reset(self)->None:
        for proc in(
            self._gyro_x,self._gyro_y,self._gyro_z,
            self._accel_x,self._accel_y,self._accel_z,
            self._light,
        ):
            proc.reset()
        self._t0_ns=time.time_ns()
        self._tick=0
        logger.debug("[SensoryEmulation] Reset to equilibrium")
