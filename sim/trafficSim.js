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
  host: '127.0.0.1', // should be supplied
  connections: undefined,
  servers: undefined,
  clients: undefined,
  verbose: false,
  debug: false,
  version: '0.0.1'
};


// specify either:
//  node util/trafficSim --host 192.168.1.5 --post 20000 --connections 10
// or if just want to start servers on this host
//  node util/trafficSim --host 192.168.1.5 --post 20000 --servers 10
// or if just want to start clients on this host
//  node util/trafficSim --host 192.168.1.5 --post 20000 --clients 9
commander
    .version('0.0.1')
    //.usage('[options] ...')
    .option('-h, --host [value]','the host ip address or dns name that is listening for a tcp/ip connection')
    .option('-p, --port <n>','the starting port for servers created which will be listening for a tcp/ip connection')
    .option('-c, --connections <n>','the # of connections to create (server/client pairs')
    .option('-s, --servers <n>','the # of servers to create (use if not specify connections')
    .option('-k, --clients <n>','the # of clients to create (use if not specify connections')
    .option('-v, --verbose','output verbose information')
    .option('-d, --debug','output debugging information')
    .parse(process.argv);

if (commander.connections !== undefined) {
  if (commander.clients !== undefined || commander.servers !== undefined) {
    if (commander.servers !== undefined) {
      console.error('cannot specify connections and server at the same time');
    }
    if (commander.clients !== undefined) {
      console.error('cannot specify connections and clients at the same time');
    }
    process.exit(1);
  }
  if (commander.connections > 0) {
    state.connections = commander.connections
  } else {
    console.error('specify connections greater than 0');
    process.exit(1);
  }
} else {
  if (commander.clients === undefined && commander.servers === undefined) {
    console.error('must specify either (connections) or (clients and/or servers)');
    process.exit(1);
  }
  if (commander.clients !== undefined && commander.clients < 1) {
    console.error('if specifying clients, must specify > 0');
    process.exit(1);
  }
  if (commander.servers !== undefined && commander.servers < 1) {
    console.error('if specifying servers, must specify > 0');
    process.exit(1);
  }
  state.clients = commander.clients;
  state.servers = commander.servers;
}
if (commander.host !== undefined) {
  state.host = commander.host;
}
if (commander.port !== undefined) {
  let port = Number.parseInt(commander.port);
  if (port < 1) {
    console.error('port must be > 0');
    process.exit(1);
  }
  state.port = port;
}
if (commander.verbose !== undefined) {
  state.verbose = commander.verbose;
}
if (commander.debug !== undefined) {
  state.debug = commander.debug;
}

console.log(`trafficSim version ${state.version}`);
// Clients can connect to servers on this VM, or
// can connect to servers on other VMs
function Client(config) {

  ++Client.count;
  this.id = Client.count;
  this.name = config.name || `Client ${this.id}`;
  this.host = config.host;
  this.port = config.port;

  this.interval = config.interval || (10 * 1000); // millis between message sends
  this.initMessageSize = config.initMessageSize || 100; // initial size
  this.messageSizeIncrement = config.messageSizeIncrement || 100; // each size increment
  this.maxMessageSize = config.maxMessageSize || 500; // max size before wrapping
  this.maxMessages = config.maxMessages || 0; // 0 means no limit BE CAREFUL!
  this.seed = config.seed || 'x';

  this.message = '';
  this.messageCount = 0;
  this.messageSizeAccumulted = 0; // accumulated size of messages

  // if not passed truthy, must perform client.connect().then()
  if (config.connect) {
    this.connect();
  }
}
// internal counter of clients connected
Client.count = 0;
// Instantiate a client to a working server
// returns Promuse resolved when established
Client.prototype.connect = function() {
  return new Promise((resolve, reject) => {
    // Establish connection
    this.client = new net.Socket();
    this.client.connect(this.port, this.host, () => {
      if (state.verbose) {
        console.log(`Client ${this.toString()} connected`);
      }
      this.client.write(message);
      resolve();
    }).on('data', (data) => {
      if (state.verbose) {
        console.log(`Client ${this.name} received: ${data}`);
      }
    }).on('close', () => {
      console.log(`Client ${this.name} connection closed`);
    });
  });
};
Client.prototype.close = function() {
  this.client.end();
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
Client.prototype.dump = function() {
  return `Client ${this.name}(${this.id})`,JSON.stringify(this, null, '  ');
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

  ++Server.count;
  this.id = Server.count;
  this.name = config.name || `Server ${this.id}`;
  this.host = config.host;
  this.port = config.port;
  this.openMessage = config.openMessage;
  this.echo = config.echo !== undefined ? config.echo : true;

  this.receivedData = 0;
  this.receivedLength = 0;
  this.lastReception = 0; // set to Date().now()

  this.server = net.createServer((socket) => {
    if (this.openMessage) {
      socket.write(this.openMessage);
    }
    // Server just echos back what it receives
    socket.pipe(socket);
  }).on('error', (err) => {
    // handle errors here
    console.error(err);
  }).on('data', (data) => {
    this.receivedData++;
    this.receivedLength += data.length;
    this.lastReception = Date.now();
  });

  this.server.listen(this.port, this.host);
  if (state.verbose) {
    console.log(`Server ${this.toString()} created and listenting on ${this.port}`);
  }
}
Server.count = 0;
Server.prototype.close = function() {
  this.server.close((err) => {
    if (state.verbose) {
      console.log('Server ${this.toString()) closed');
    }
    if (err) {
      console.error('Server ${this.toString())')
    }
  });
};
Server.prototype.toString = function() {
  return `Server ${this.name}(${this.id})`;
};
// exists between a client and server
function Connection(config) {
  //
  this.client = config.client;
  this.server = config.server;
}

// Create specified # of clients to connect to state.host at port state.post + i
if (state.clients) {
  for (let i = 0; i < state.clients; i++) {
    let client = new Client({
      name: `Client ${i + 1}`,
      host: state.host,
      port: state.port + i,
      seed: String.fromCharCode(97 + i), // 'a', 'b', ...
      maxMessages: 1
    });
  }
}
if (state.servers) {
  for (let i = 0; i < state.servers; i++) {
    let client = new Server({
      name: `Server ${i + 1}`,
      host: state.host,
      port: state.port + i,
      openMessage: `Greetings from Server ${i}`,
      maxMessages: 1
    });
  }
}
if (state.connections) {
  console.log('connections not implemented yet');
}