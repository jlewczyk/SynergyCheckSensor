const moment = require('moment');
const commonLib = require('../common');
const request    = require('request-promise-native');

let logger;

//--------------------------- APIs -------------------------------
let state;

let reportTimer; // keep it out of the state object

// return true if the sensor has that interfaceUid assigned to it
function getDefinedInterface(uid, sensor) {
  if (sensor && typeof(uid) !== 'undefined') {
    connection = sensor.connections.find(c => c.interfaceUid === uid);
    return connection;
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
  const memoryUsed = process.memoryUsage().heapUsed / 1024 / 1024; // in megabytes
  state.memory = `${Math.round(memoryUsed * 100) / 100} MB`;
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
//--------------------- Handle sensorReport from sensor to this Agent ---------------------------
// Handle a report from a Sensor to this Agent
exports.postSensorReport = function(req, res) {
  logger.debug(`postSensorReport`);
  const swagger = req.swagger;
  const params = swagger.params;
  const body = params.body.value;
  const errors = [];

  let sensor;
  let timestampDate;
  let timestampISO;

  // make report more readable on logger output
  function ppReport(body) {
    function pl(x, w) {
      return `${x}                    `.substr(0, w);
    }
    function pr(x, w) {
      return `                  ${x}`.substr(-w);
    }
    const copy = JSON.parse(JSON.stringify(body));
    const connections = copy.snapshot.connections;
    delete copy.snapshot.connections;
    logger.verbose(`snapshot = ${JSON.stringify(copy.snapshot)}`);
    //              123456789012 123456789 12345678901 123456789012 123456789012 123456789012
    //              1234567890123456789012345678901234567890123456789012345678901234567890123
    logger.verbose(`interfaceUid charCount packetCount disconnected sourceNoPing destinationNoPing`);
    (connections || []).forEach(conn => {
      logger.verbose(`${pl(conn.interfaceUid, 12)} ${pl(conn.charCount, 9)} ${pl(conn.packetCount, 11)} ${pl(conn.disconnected, 12)} ${pl(conn.sourceNoPing, 12)} ${pl(conn.destinationNoPing, 12)}`);
    });
    logger.verbose(`stats    = ${JSON.stringify(copy.stats)}`);
  }
  //
  try {
    if (state.autoConfig && !state.sensors) {
      res.status(405).send({status: 'error', errors: ['agent has not been auto configured']});
      if (state.debug) {
        logger.error('postSensorReport errors: ' + JSON.stringify(errors, null, '  '));
      }
      return;
    }
    if (body && typeof(body.snapshot) === 'object') {
      // de-structure
      let {sensorId, customerId, timestamp, transactionId, duration, connections} = body.snapshot;
      if (connections && connections.length) {
        if (state.verbose) {
          ppReport(body);
        } else {
          logger.debug(`postSensorReport received ${JSON.stringify(body)}`);
        }
      } else {
        //  one line since there are no connections with any info
        logger.debug(`postSensorReport received ${JSON.stringify(body)}`);
      }

      // validate sensorId?
      if (typeof(sensorId) === 'undefined') {
        errors.push('sensorId is required');
      } else {
        sensor = state.sensors.find(o => o.sensor_id === sensorId)
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

      if (errors.length === 0) {
        // process and validate each connection update in report
        if (connections && connections.length) {
          connections.forEach(ic => { // ic is incoming connection update
            let interfaceUid; // unique identifier of connection
            let charCount; // # of characters received in packets over sampling period
            let packetCount; // # of packets received during sampling period
            let connection; // found connection registered with interfaceUid
            let disconnected; // true if nmap reports that no connection exists betwen source and target on specified port
            let sourceNoPing; // true if attempt to ping source server failed
            let destinationNoPing; // true if attempt to ping target server failed


            if (!ic.interfaceUid) {
              errors.push(`interfaceUid is required`);
            } else if (!getDefinedInterface(ic.interfaceUid, sensor)) {
              errors.push(`interfaceUid ${ic.interfaceUid} not expected. as it is not in sensor ${sensorId} configuration`)
            } else {
              interfaceUid = ic.interfaceUid;
            }

            // process the character count being reported (if any)
            if (typeof(ic.charCount) !== 'undefined') {
              if (typeof(ic.charCount) === 'number') {
                charCount = ic.charCount;
                if (charCount < 0) {
                  errors.push(`cannot report negative charCount (${charCount}) for interfaceUid ${interfaceUid}`);
                }
              } else if (typeof(ic.charCount) === 'string') {
                if (/^-\d+$/.test(ic.charCount)) {
                  charCount = Number.parseInt(ic.charCount);
                  if (charCount < 0) {
                    errors.push(`cannot report negative charCount (${charCount}) for interfaceUid ${interfaceUid}`);
                  }
                } else {
                  errors.push(`expected number or parsable number string, got ${typeof(ic.charCount)} for interfaceUid ${interfaceUid}`);
                }
              } else {
                errors.push(`expected number or parsable number string, got ${typeof(ic.charCount)} for interfaceUid ${interfaceUid}`);
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

            if (typeof(ic.destinationNoPing) !== 'undefined') {
              if (typeof(ic.destinationNoPing) === 'boolean') {
                destinationNoPing = ic.destinationNoPing;
              } else {
                errors.push(`destinationNoPing if present must be boolean, but it is ${typeof(ic.destinationNoPing)}`);
              }
            }

            if (errors.length === 0) {

              // note the sensor contributing to the next report
              if (state.sensorsAccum.indexOf(sensorId) === -1) {
                state.sensorsAccum.push(sensorId);
              }

              let connection = state.connectionsAccum.find(o => o.interfaceUid === interfaceUid);
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
                  interfaceUid: interfaceUid,
                  charCount: charCount || 0,
                  packetCount: packetCount || 0,
                  disconnected: disconnected,
                  sourceNoPing: sourceNoPing,
                  destinationNoPing: destinationNoPing,
                  lastMessage: charCount ? timestampISO : undefined
                });
              }
            }
          });
        }
      }
      if (body.stats) {
        // sensor configured to also sends some stats on its internals
        // so we can expose them through a call to the agent
        if (state.verbose) {
          logger.info(`sensor ${sensorId} stats: ${JSON.stringify(body.stats)}`);
        }
        // merge stats
        state.sensorStats[sensorId] = body.stats;
      }
      if (errors.length) {
        res.status(405).send({
            status: 'errors',
            errors: errors
          }
        );
        logger.error('postSensorReport errors: ' + JSON.stringify(errors, null, '  '));
      } else {
        const response = {
          status: 'ok',
          newConfig: haveNewSensorConfig(sensorId)
        };
        res.send(response);
        logger.verbose(`postSensorReport response ${JSON.stringify(response)}`)
      }
    } else {
      errors.push('no snapshot property');
      res.status(405).send({
        status: 'errors',
        errors: errors
      });
      logger.debug('postSensorReport errors: ' + JSON.stringify(errors, null, '  '));
    }
  } catch (ex) {
    logger.error(`postSensorReport exception ${ex}`);
  }
};
// @return the new configuration object for a sensor if a newer configuration for the specified sensor has arrived
// @return false if no new configuration is available (which is most of the time)
// This tells the sensor in the response to a sensor's sensorReport that a new config is included
function haveNewSensorConfig(sensorId) {
  // agent polls synergycheck periodically for config and indexes each sensor's config and compares date of it
  // to determine if sensor is due for a fresher config.  It informs the sensor via the response to the
  // sensor's periodic sensor report.
  if (state.newAutoConfig) {
    const newI = (state.newAutoConfig.sensors || []).findIndex(s => s.sensor_id === sensorId);
    if (newI > -1) {
      const newSensorConfig = state.newAutoConfig.sensors[newI];
      logger.debug(`newAutoConfig found entry for sensor ${sensorId}`);

      state.newAutoConfig.sensors.splice(newI, 1); // remove from list of new configurations
      // replace or add it to list of current sensor configurations
      const i = state.sensors.findIndex(s => s.sensor_id === sensorId);

      if (newSensorConfig.delete) {
        // removing a sensor from control by this agent
        // may be accompanied by other agent getting specification for the sensor
        // this sensorReport's response will instruct the sensor to get config from other agent_id specified!
        state.sensors.splice(i, 1);
      } else {
        if (i > -1) {
          // replace existing config with new config
          state.sensors.splice(i, 1, newSensorConfig);
        } else {
          // adding a new sensor
          state.sensors.push(newSensorConfig);
        }
      }
      return newSensorConfig;
    }
  }
  return false;
}
// Sensor is reporting that it has started
exports.postSensorStart = function(req, res) {
  res.status(500).send({ status: 'error', errors: ['not implemented']});
};
// Sensor is reporting that it has stopped
exports.postSensorStop = function(req, res) {
  res.status(500).send({ status: 'error', errors: ['not implemented']});
};
// Can ask agent - what was the last Agent report that was sent?
exports.getSensorPriorReport = function(req, res) {
  res.send(state.agentReports.priorReport || {});
};
// Can ask agent for an agent report on demand, not waiting for next report period
exports.getSensorNextReport = function(req, res) {
  res.send(generateAgentReport());
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
  // Validate agentId specified on startup.
  // assume agent knows its own valid id!
  if (typeof(agentId) === 'undefined') {
    errors.push(`agentId is required`);
  } else if (agentId !== state.config.agent.agentId) {
    errors.push(`unknown agentId "${agentId}"`);
  }
  if (typeof(sensorId) === 'undefined') {
    errors.push(`sensorId is required`);
  } else {
    const sensor = state.sensors.find(s => `${s.sensor_id}` === sensorId);
    if (sensor) {
      // send along specified Sensor's configuration
      res.send({
        name: sensor.name,
        version: sensor.version,
        customer_id: customerId, // the customer whose data is being monitored
        agent_id: agentId, // the agent that the sensor requested configuraiton from
        sensor_id: sensorId, // will match what the sensor requesting configuration
        deviceName: sensor.deviceName, // external name of ethernet device (typically configured in sensor's config file)
        device: sensor.device, // identifier of ethernet device to monitor (used to configure pcap, typically configured in sensor's config file)
        samplePeriod: sensor.samplePeriod, // rate to report the sampling of the ethernet device
        connections: sensor.connections // array of interfaces to monitor
      });
    } else {
      errors.push(`sensorId ${sensorId} not found in Agent's configuration`);
    }
  }
  if (errors.length) {
    res.status(405).send({status: 'error', errors: errors});
  }
};
// queue requests so we can retry failed ones (e.g. SynergyCheck server is temporarily unavailable
// Does give up after so many retries.  What to do with those abandoned agentReports?
exports.sendReport = function() {

  const theReport = exports.generateAgentReport();
  const postReportUrl = `${commonLib.getProtoHostPort()}${state.synergyCheck.apiBase}agentReport?tx=${theReport.tx}`;
  state.agentReportQueue.push([postReportUrl, theReport, 0]);

  if (!state.agentReports.sending) {
    // kick off queue processing
    sendAgentReport(state.agentReportQueue.shift());
  }
  //
  function sendAgentReport(item) {
    if (!item) {
      return;
    }
    //indicate we don't need to call sendAgentReport again (until it goes falsey)
    state.agentReports.sending = Date.now();
    request({
      method: 'POST',
      strictSSL: !state.synergyCheck.weakSSL,
      uri: item[0], // postReportUrl
      body: item[1], // theReport
      headers: {
        'Authorization': `Bearer ${state.synergyCheck.jwt}`
      },
      json: true // automatically stringifies body
    }).then(reportResponse => {
      logger.debug(`agentReport response: ${JSON.stringify(reportResponse)}`);
      state.agentReports.sent++;
      // remember what you just successfully sent
      state.agentReports.priorReport = theReport;
      // After agentReport has been processed, SynergyCheck will evaluate the reporting agent and its sensors
      // for any new configuration.  If so, then the reportReponse.newConfig contains that new configuration.
      // If a sensor configuration changed was included, then that will be communicated to the sensor
      // as a response to its sensorReport.
      if (reportResponse.newConfig) {
        logger.info(`New configuration received in response to POST agentReport`);
        // todo - validate sensor configuration

        // queue up the new configuration object for sampling by haveNewSensorConfig
        state.newAutoConfig = reportResponse.newConfig;
      }
      sendSomeMore();
    }).catch(reqErr => {
      state.agentReports.errors++;
      logger.error(`Error from SynergyCheck for agentReport tx=${theReport.tx}, ${reqErr}`);

      function isUnauthorized(err) {
        return err.statusCode === 401;
      }
      function resendAfterDelay(item) {
        // resend after delay, but only a certain # of times before "giving up"
        item[2] = item[2] + 1; // retries
        if (item[2] < state.agentReports.maxRetries || 1) {
          // Will retry this agentReport, so put it back at the head of the queue
          state.agentReportQueue.unshift(item);
          setTimeout(() => {
            sendAgentReport(state.agentReportQueue.shift());
          }, state.agentReports.sendDelay || 5000);
        } else {
          giveUpOn(item);
          sendSomeMore();
        }
      }

      if (isUnauthorized(reqErr)) {
        commonLib.getAuthenticate().then(jwtToken => {
          resendAfterDelay(item);
        }, authErr => {
          logger.error(`Failure to reauthorize! ${authErr}, exiting...`);
          process.exit(1);
        });
      } else {
        resendAfterDelay(item);
      }
    });
    if (state.verbose) {
      logger.info(JSON.stringify(theReport, null, '  '));
    }
  }
  //
  function sendSomeMore() {
    if (state.agentReportQueue.length) {
      logger.debug(`agentReportQueue has ${state.agentReportQueue.length} items`);
      setTimeout(() => {
        sendAgentReport(state.agentReportQueue.shift());
      }, state.agentReports.sendDelay || 5000);
    } else {
      logger.debug(`agentReportQueue is empty`);
      // Indicate that it is ok to call sendAgentReport from sendReport
      state.agentReports.sending = null;
    }
  }
  //
  function giveUpOn(item) {
    logger.error(`giving up on ${item[1].tx} after ${item[2]} retries`);
    // todo - write to file system or some log?
  }
};
// return object containing body of post request to be sent to SynergyCheck.com server
exports.generateAgentReport = function() {
  // generate unique transaction number
  // by combining id of the agent, a time factor, and a counter
  state.transactionCounter++;
  const transactionId = `${state.agent.agentId}|${Math.floor(state.startedMills / 100 % 1000000)}|${state.transactionCounter}`;
  state.lastTransactionId = transactionId;

  const snapshot = {
    cid: state.synergyCheck.customerId,
    aid: state.agent.agentId,
    tx: transactionId,
    ts: moment().format(), // ISO with timezone // new Date().toISOString(),
    dur: state.report.dur, // string
    // sensors: sensorsAccum.slice(0),
    int: state.connectionsAccum.map(o => {
      return {
        cnid: o.connectionId,
        iid: o.interfaceUid,
        cc: o.charCount || 0,
        pc: o.packetCount || 0,
        ldts: o.lastMessageTimestamp, // ignored by SynergyCheck
        // lcts: '?', // ignored by SynergyCheck, computed based on ts of agentReport
        dis: o.disconnected,
        snp: o.sourceNoPing,
        dnp: o.destinationNoPing
      };
      // sort for consistency in logs only
    }).sort((a, b) => a.iid < b.iid ? -1 : (a.iid === b.iid ? 0 : 1))
  };
  state.connectionsAccum.length = 0; // reset accumulator for next report
  state.sensorsAccum.length = 0;

  if (state.report.compress) {
    // remove reporting those connections with no change from last report
    if (state.agentReports.priorReport) {
      // filter the connections based on if they report anything useful to state change of connection
      snapshot.int = snapshot.int.filter(o => {
        if (o.charCount) {
          return true; // always report if has measured character traffic
        }
        if (o.dis || o.snp || o.dnp) {
          return true; // always report if any disconnected or no pings
        }
        // no messages, no disconnected, snp or dnp, check if change from prior status
        let connectionPrior = state.agentReports.priorReport.int.find(c => c.iid === o.iid);
        if (connectionPrior) {
          // all false, so a change if any were previously true
          return (connectionPrior.dis !== o.dis) || (connectionPrior.snp !== o.snp) || (connectionPrior.dnp !== o.dnp);
        }
        return true; // always report if no prior to compare with
      });
    }
  }
  if (state.debug) {
    logger.debug(`agentReport: ${JSON.stringify(snapshot)}`);
  }
  return snapshot;
};
//
// start an interval timer to send updates to synergyCheck service in the cloud
exports.startReporting = function() {
  const period = state.report.period || 60000;
  reportTimer = setInterval(function () {
    logger.debug(`time to send report! ${new Date().toISOString()}`);
    exports.sendReport();
  }, period);
  logger.info(`AgentReports started at ${new Date().toISOString()}, once per ${period}`);
};
//
exports.stopReporting = function() {
  if (reportTimer) {
    clearInterval(reportTimer);
    reportTimer = null;
  }
  logger.info(`AgentReports stopped at ${new Date().toISOString()}`);
};

