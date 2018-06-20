// run this to simulate a number of interface connections with predictable data
// so they can be monitored to check the effectiveness and performance of
// the SynergyCheck sensors and concentrator agent.
//
// Provide configuration information in trafficSim.json
// >node trafficSim.js

const commander = require('commander');
const net = require('net');
const fs = require('fs');

const state = {
  connections: 1,
  verbose: false,
  debug: false,
  version: '0.0.1'
};

console.log(`trafficSim version ${state.version}`);
// Clients can connect to servers on this VM, or
// can connect to servers on other VMs
function Client(config) {
  var that = this;

  ++Client.count;
  this.id = Client.count;
  this.name = config.name || `client ${this.id}`;
  this.port = config.port;
  this.host = config.host;

  this.interval = config.interval || (10 * 1000); // between message sends
  this.initMessageSize = config.initMessageSize || 100; // initial size
  this.messageSizeIncrement = config.messageSizeIncrement || 100; // each size increment
  this.maxMessageSize = config.maxMessageSize || 500; // max size before wrapping
  this.maxMessages = config.maxMessages || 0; // 0 means no limit BE CAREFUL!
  this.seed = config.seed || 'x';

  this.message = '';
  this.messageCount = 0;
  this.messageSizeAccumulted = 0; // accumulated size of messages

  // Establish connection
  this.client = new net.Socket();
  this.client.connect(this.port, this.host, () => {
    console.log('Connected');
    that.client.write(message);
    that.client.end();
  });

  this.client.on('data', (data) => {
    console.log(`Client ${that.name} received: ${data}`);
  });

  this.client.on('close', () => {
    console.log(`Client ${that.name} connection closed`);
  });
}
// internal counter of clients connected
Client.count = 0;
Client.prototype.close = function() {
  this.client.destroy(); // kill client after server's response
};
// compute the next message to send
// return false if no message to be sent (exceeded threshold)
Client.prototype.nextMessage = function() {
  if (this.messageCount < this.maxMessages) {
    this.message.length += this.messageSizeIncrement;
    if (this.message.length > this.maxMessageSize) {
      this.message.length = this.initMessageSize;
    }
    this.message = makeMessageString(this.seed, this.message.length)
    return true;
  }
  if (state.verbose) {
    console.log(`Client reached max message threshold of ${this.maxMessages}`);
  }
  return false;
};
Client.prototype.sendMessage = function() {
  if (this.nextMessage()) {
    this.client.write(this.message);
    this.messageSizeAccumulted + this.message.length;
  }
};
Client.prototype.toString = function() {
  return `Client ${this.name}(${this.id})`;
};
//
//
//
function makeMessageString(seed, length) {
  // dumb
  var x = '';
  while (x.length < length) {
    x += seed;
  }
  return x.substr(0, length);
}
// Each Server runs on this VM and listens on a unique port
function Server(config) {
  this.port = config.port;

}
//
function Connection(config) {
  //
}

function oneConnection(connection) {

}
