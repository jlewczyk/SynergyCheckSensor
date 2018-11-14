const moment = require('moment');
const commonLib = require('../common');

let logger;

//--------------------------- APIs -------------------------------
let state;

// return true if the sensor has that interfaceId assigned to it
function isDefinedInterface(interfaceId, sensor) {
  if (sensor && typeof(icId) !== 'undefined') {
    connection = sensor.connections.find(c => c.interfaceId === icId);
    if (!connection) {
      errors.push(`unregistered interfaceId "${icId}"`);
    }
  }
}
//
exports.init = function(oState) {
  logger = commonLib.getLogger();
  logger.debug('agentRoutes.init()');
  state = oState;
};
//
// is the server up and responding?
exports.getPing = function(req, res) {
  res.status(200).send({
    timestamp: moment().format() // ISO with timezone new Date().toISOString()
  });
};
// state
exports.getState = function(req, res) {
  res.status(200).send(state);
};
// start sending agentReports periodicallt
exports.postStartReports = function(req, res) {
  logger.debug('postStartReports');
  exports.startReporting();
  res.send({status: 'ok', message: 'agentReports started'});
};
// Stop sending agentReports
exports.postStopReports = function(req, res) {
  logger.debug('postStopReports');
  exports.stopReporting();
  res.send({ status: 'ok', message: 'agentReports stopped'});
};
//--------------------- Sensor reporting to this Agent ---------------------------
// Sensor reports data to this agent
exports.postSensorReport = function(req, res) {
  logger.debug(`postSensorReport`);
  const swagger = req.swagger;
  const params = swagger.params;
  const body = params.body.value;
  const errors = [];

  let sensor;
  let timestampDate;
  let timestampISO;

  if (state.autoConfig && !state.config.sensors) {
    res.status(405).send({ status: 'error', errors: ['agent has not been auto configured'] });
    if (state.debug) {
      logger.error('errors: ' + JSON.stringify(errors, null, '  '));
    }
    return;
  }
  if (body && typeof(body.snapshot) === 'object') {
    // de-structure
    let {sensorId, customerId, timestamp, transactionId, duration, connections} = body.snapshot;
    if (state.debug) {
      logger.info(JSON.stringify(body, null, '  '));
    }

    // validate sensorId?
    if (typeof(sensorId) === 'undefined') {
      errors.push('sensorId is required');
    } else {
      sensor = state.config.sensors.find(o => o.sensorId === sensorId)
      if (!sensor) {
        errors.push(`unrecognized sensorId "${sensorId}"`);
      }
    }
    // validate customerId
    if (typeof(customerId) === 'undefined') {
      errors.push('customerId is required');
    } else if (state.config.synergyCheck.customerId !== customerId) {
      errors.push(`unrecognized customerId "${customerId}"`);
    }

    // validate timestamp
    if (typeof(timestamp) === 'undefined') {
      errors.push('timestamp is required');
    } else {
      try {
        timestampDate = new Date(timestamp);
        if (Number.isNaN(timestampDate.getTime())) {
          errors.push(`invalid format for timestamp "${timestamp}"`);
          timestampDate = undefined;
          timestampISO = '?';
        } else {
          // so all the connection timestamps are the same
          timestampISO = timestampDate.toISOString();
        }
      } catch (exDate) {
        errors.push(`invalid format for timestamp "${timestamp}"`);
        timestampDate = undefined;
        timestampISO = '?';
      }
    }

    // validate duration - todo

    // process and validate each connection update in report
    if (connections && connections.length) {
      connections.forEach(ic => { // ic is incoming connection update
        let interfaceId; // unique identifier of connection
        let charCount; // # of characters received in packets over sampling period
        let packetCount; // # of packets received during sampling period
        let connection; // found connection registered with icId
        let disconnected; // true if nmap reports that no connection exists betwen source and target on specified port
        let sourceNoPing; // true if attempt to ping source server failed
        let targetNoPing; // true if attempt to ping target server failed


        if (!ic.interfaceId) {
          errors.push(`interfaceId is required`);
        } else if (!isDefinedInterface(ic.interfaceId, sensor)) {
          errors.push(`interfaceId ${ic.interfaceId} not expected. as it is not in sensor ${sensorId} configuration`)
        } else {
          interfaceId = ic.interfaceId;
        }

        // process the character count being reported (if any)
        if (typeof(ic.charCount) !== 'undefined') {
          if (typeof(ic.charCount) === 'number') {
            charCount = ic.charCount;
            if (charCount < 0) {
              errors.push(`cannot report negative charCount (${charCount}) for interfaceId ${icId}`);
            }
          } else if (typeof(ic.charCount) === 'string') {
            if (/^-\d+$/.test(ic.charCount)) {
              charCount = Number.parseInt(ic.charCount);
              if (charCount < 0) {
                errors.push(`cannot report negative charCount (${charCount}) for interfaceId ${icId}`);
              }
            } else {
              errors.push(`expected number or parsable number string, got ${typeof(ic.charCount)} for interfaceId ${icId}`);
            }
          } else {
            errors.push(`expected number or parsable number string, got ${typeof(ic.charCount)} for interfaceId ${icId}`);
          }
        }

        if (typeof(ic.packetCount) !== 'undefined') {
          if (typeof(ic.packetCount) === 'string') {
            if (/^\d+$/.test(ic.packetCount)) {
              packetCount = Number.parseInt(ic.packetCount);
              if (packetCount < 0) {
                errors.push(`packetCount must be >= 0, ${packetCount}`);
              }
            } else {
              errors.push(`packetCount not expected form '${ic.packetCount}'`);
            }
          } else if (typeof(ic.packetCount) === 'number') {
            packetCount = ic.packetCount;
            if (packetCount < 0) {
              errors.push(`packetCount must be >= 0, ${packetCount}`);
            }
          } else {
            errors.push(`packetCount not expected form '${ic.packetCount}'`);
          }
        }

        if (typeof(ic.disconnected) !== 'undefined') {
          if (typeof(ic.disconnected) === 'boolean') {
            disconnected = ic.disconnected;
          } else {
            errors.push(`disconnected if present must be boolean, but it is ${typeof(ic.disconnected)}`);
          }
        }

        if (typeof(ic.sourceNoPing) !== 'undefined') {
          if (typeof(ic.sourceNoPing) === 'boolean') {
            sourceNoPing = ic.sourceNoPing;
          } else {
            errors.push(`sourceNoPing if present must be boolean, but it is ${typeof(ic.sourceNoPing)}`);
          }
        }

        if (typeof(ic.targetNoPing) !== 'undefined') {
          if (typeof(ic.targetNoPing) === 'boolean') {
            targetNoPing = ic.targetNoPing;
          } else {
            errors.push(`targetNoPing if present must be boolean, but it is ${typeof(ic.targetNoPing)}`);
          }
        }

        if (errors.length === 0) {

          // note the sensor contributing to the next report
          if (state.sensorsAccum.indexOf(sensorId) === -1) {
            state.sensorsAccum.push(sensorId);
          }

          let connection = state.connectionsAccum.find(o => o.interfaceId === icId);
          if (connection) {
            if (charCount) {
              // have some volume of data to report
              connection.charCount += charCount;
              connection.lastMessageTimestamp = timestampISO;
            }
            if (packetCount) {
              connection.packetCount += packetCount;
            }
            if (typeof(ic.disconnected) === 'boolean') {
              // sensor reported either true of false (when changed)
              // the last one reported in the reporting period will be passed on
              if (!!connection.disconnected !== ic.disconnected) {
                connection.lastChangeInConnectionTimestamp = timestampISO;
              }
              connection.disconnected = ic.disconnected;
            }
            // connection.timestamps.push(timestampIso);
          } else {
            state.connectionsAccum.push({
              interfaceId: interfaceId,
              charCount: charCount || 0,
              packetCount: packetCount || 0,
              disconnected: disconnected,
              sourceNoPing: sourceNoPing,
              targetNoPing: targetNoPing,
              lastMessage: charCount ? timestampISO : undefined
            });
          }
        }
      });
      if (errors.length) {
        res.status(405).send({ status: 'errors', errors: errors });
        if (state.debug) {
          logger.error('errors: ' + JSON.stringify(errors, null, '  '));
        }
      } else {
        res.status(200).send({status: 'ok'});
        if (state.debug) {
          logger.info('ok');
        }
      }
    }
  } else {
    res.status(405).send({ status: 'errors', errors: ['no snapshot property']});
    if (state.debug) {
      logger.error('errors: ' + JSON.stringify(errors, null, '  '));
    }
  }
};
// Sensor is reporting that it has started
exports.postSensorStart = function(req, res) {
  res.status(500).send({ status: 'error', errors: ['not implemented']});
};
// Sensor is reporting that it has stopped
exports.postSensorStop = function(req, res) {
  res.status(500).send({ status: 'error', errors: ['not implemented']});
};
// Can ask agent - what was that last report that was sent?
exports.getSensorPriorReport = function(req, res) {
  res.send(state.priorReport || {});
};
// Can ask agent for a report on demand, not waiting for next report period
exports.getSensorNextReport = function(req, res) {
  res.send(getReport());
};
// Sensor asks Agent for its configuration
// /api/v1/sensor/autoConfig
exports.getSensorAutoConfig = function(req, res) {
  logger.debug(`getSensorAutoConfig`);
  const swagger = req.swagger;
  const params = swagger.params;
  let errors = [];
  const sensorId = params.sensorId ? params.sensorId.value : undefined;
  const agentId = params.agentId ? params.agentId.value : undefined;
  const customerId = params.customerId ? params.customerId.value : undefined;
  logger.info(`getSensorAutoConfig?sensorId=${sensorId}&agentId=${agentId}&customerId=${customerId}`);
  // validate customerId
  if (typeof(customerId) === 'undefined') {
    errors.push(`customerId is required`);
  } else if (customerId !== state.config.synergyCheck.customerId) {
    errors.push(`unknown customerId "${customerId}"`);
  }
  // todo - validate agentId specified on startup.
  // assume agent knows its own valid id!
  if (typeof(agentId) === 'undefined') {
    errors.push(`agentId is required`);
  } else if (agentId !== state.config.agent.agentId) {
    errors.push(`unknown agentId "${agentId}"`);
  }

  if (typeof(sensorId) === 'undefined') {
    errors.push(`sensorId is required`);
  } else {
    const sensor = state.config.sensors.find(s => s.sensorId === sensorId);
    if (sensor) {
      // send along specified agent's configuration
      res.send({
        name: sensor.name,
        version: sensor.version,
        customerId: customerId, // the customer whose data is being monitored
        agentId: agentId, // the agent that the sensor requested configuraiton from
        sensorId: sensorId, // will match what the sensor requesting configuration
        deviceName: sensor.deviceName, // external name of ethernet device
        device: sensor.device, // identifier of ethernet device to monitor (used to configure pcap)
        sampleRate: sensor.sampleRate, // rate to report the sampling of the ethernet device
        connections: sensor.connections // array of interfaces to monitor
      });
    } else {
      errors.push('sensor not found');
    }
  }
  if (errors.length) {
    res.status(405).send({status: 'error', errors: errors});
  }
};


exports.sendReport = function() {
  const theReport = exports.getReport();
  postReportUrl = `${state.getProtoHostPort()}/${state.synergyCheck.apiBase}/agentReport?tx=${theReport.transactionId}`;
  request({
    method: 'POST',
    uri: postReportUrl,
    body: theReport,
    headers: {
      'Authorization': `Bearer ${state.synergyCheck.jwt}`
    },
    json: true // automatically stringifies body
  }).then(obj => {
    state.agentReportsSent++;
    logger.debug(JSON.stringify(obj));
  }).catch(err => {
    state.agentReportErrors++;
    logger.error(`Error from SynergyCheck for agentReport tx=${theReport.transactionId}, ${err}`);
  });
  if (state.verbose) {
    logger.info(JSON.stringify(theReport, null, '  '));
  }
  // remember what you just sent
  state.priorReport = theReport;

};
// return object containing body of post request to be sent to SynergyCheck.com server
exports.getReport = function() {
  // generate unique transaction number
  // by combining id of the agent, a time factor, and a counter
  state.transactionCounter++;
  const transactionId = `${state.config.agent.agentId}|${Math.floor(state.startedMills / 100 % 1000000)}|${state.transactionCounter}`;
  state.lastTransactionId = transactionId;

  const snapshot = {
    cid: state.config.synergyCheck.customerId,
    aid: state.config.agent.agentId,
    tx: transactionId,
    ts: moment().format(), // ISO with timezone // new Date().toISOString(),
    dur: state.config.report.period,
    // sensors: sensorsAccum.slice(0),
    int: state.connectionsAccum.map(o => {
      return {
        cnid: o.connectionId,
        cc: o.charCount || 0,
        pc: o.packetCount || 0,
        ldts: o.lastMessageTimestamp, // ignored by SynergyCheck
        // lcts: '?', // ignored by SynergyCheck, computed based on ts of agentReport
        dis: o.disconnected,
        snp: o.sourceNoPing,
        tnp: o.targetNoPing
      };
    })
  };
  state.connectionsAccum.length = 0; // reset accumulator for next report
  state.sensorsAccum.length = 0;

  if (state.config.report.compress) {
    // remove reporting those connections with no change from last report
    if (priorReport) {
      snapshot.connections = snapshot.connections.filter(o => {
        if (o.charCount) {
          return true; // always report if has messages
        }
        // no messages, check if change in disconnected? status
        if (typeof(o.disconnected) !== 'undefined') {
          // we have a value for disconnected
          let connectionPrior = priorReport.connections.find(c => c.connectionId === o.connectionId);
          if (connectionPrior) {
            return connectionPrior.disconnected !== o.disconnected;
          }
          // we had no value prior
          return true;
        }
        // no value for disconnected, so no change assumed from last report
        return false;
      });
    }
  }
  return snapshot;
};
//

// start an interval timer to send updates to synergyCheck service in the cloud
exports.startReporting = function() {
  const period = state.report.period || 60000;
  state.timer = setInterval(function () {
    logger.info(`time to send report! ${new Date().toISOString()}`);
    agentRoutes.sendReport();
  }, period);
  logger.info(`AgentReports started at ${new Date().toISOString()}, once per ${period}`);
};
exports.stopReporting = function() {
  if (state.timer) {
    clearInterval(state.timer);
    state.timer = null;
  }
  logger.info(`AgentReports stopped at ${new Date().toISOString()}`);
};

