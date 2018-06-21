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
  maxMessages: 0, // defaults to no limit on # of messages sent
  report: true,
  verbose: false,
  debug: false,
  version: '0.0.1'
};

const clients = [];
const servers = [];
const connections = [];

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
    .option('-x, --max <n>','the max # of messages each client sends')
    .option('-r, --report','output report at close of client or server')
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
if (commander.max !== undefined) {
  let maxMessages = Number.parseInt(commander.max);
  if (maxMessages < 0) {
    console.error('maxMessages must be >= 0');
    process.exit(1);
  }
  state.maxMessages = maxMessages;
}
if (commander.report !== undefined) {
  state.report = commander.report;
}
if (commander.verbose !== undefined) {
  state.verbose = commander.verbose;
}
if (commander.debug !== undefined) {
  state.debug = commander.debug;
}

console.log(`trafficSim version ${state.version}`);

if (state.verbose || state.debug) {
  console.log(JSON.stringify(state, null, 2));
}
// Clients can connect to servers on this VM, or
// can connect to servers on other VMs
function Client(config) {

  ++Client.count;
  this.id = Client.count;
  this.name = config.name || `Client ${this.id}`;
  this.host = config.host;
  this.port = config.port;

  this.interval = config.interval || (10 * 1000); // 10 seeconds in millis between message sends
  this.initMessageSize = config.initMessageSize || 100; // initial size
  this.messageSizeIncrement = config.messageSizeIncrement || 100; // each size increment
  this.maxMessageSize = config.maxMessageSize || 500; // max size before wrapping
  this.maxMessages = config.maxMessages || state.maxMessages; // 0 means no limit BE CAREFUL!
  this.seed = config.seed || 'x';

  this.messageSize = this.initMessageSize;
  this.message = '';
  this.messageCount = 0;
  this.totalCharactersSent = 0; // accumulated size of messages

  // if not passed truthy, must perform client.connect() which return promise
  // config.connect is by default falsey
  if (config.connect) {
    this.connect();
  }
}
// internal counter of clients connected
Client.count = 0;
// Instantiate a client to a working server
// returns Promuse resolved when established
Client.prototype.connect = function() {
  return new Promise((resolve) => {
    // Establish connection
    this.client = new net.Socket();
    this.client.connect(this.port, this.host, () => {
      if (state.verbose) {
        console.log(`Client ${this.toString()} connected`);
      }
      this.startWriteMessages();
      resolve(this);
    }).on('data', (data) => {
      if (state.verbose) {
        console.log(`Client ${this.name} received: ${data}`);
      }
    }).on('close', () => {
      console.log(`Client ${this.toString()} connection closed`);
      if (state.report) {
        console.log(`messages sent: ${this.messageCount}`);
        console.log(`total characters sent: ${this.totalCharactersSent}`)
      }
    }).on('error', (err) => {
      console.error(`Client ${this.name} connection error: ${err}`);
    });
  });
};
Client.prototype.close = function() {
  this.client.end();
  this.client.destroy(); // kill client after server's response
};
// automatic send messages, based on config
Client.prototype.startWriteMessages = function() {
  this.intervalObj = setInterval(() => {
    if (!this.sendMessage()) {
      clearInterval(this.intervalObj);
      this.close();
    }
  }, this.interval);
};
// compute the next message to send
// return false if no message to be sent (exceeded threshold)
Client.prototype.computeNextMessage = function() {
  // this.maxMessages === 0 means no limit
  if (!this.maxMessages || (this.messageCount < this.maxMessages)) {
    this.message = makeMessageString(this.seed, this.messageSize);
    // next message size computed
    this.messageSize += this.messageSizeIncrement;
    if (this.messageSize > this.maxMessageSize) {
      this.messageSize = this.initMessageSize;
    }
    this.messageCount++;
    return true;
  }
  if (state.verbose) {
    console.log(`Client reached max message threshold of ${this.maxMessages}`);
  }
  return false;
};
Client.prototype.sendMessage = function() {
  if (this.computeNextMessage()) {
    this.client.write(this.message);
    this.totalCharactersSent += this.message.length;
    return true;
  }
  return false;
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

  this.totalCharactersReceived = 0;
  this.messagesReceived = 0;
  this.lastReception = 0; // set to Date().now()
  if (state.verbose) {
    console.log(`Server ${this.toString()} created`);
  }
  // if not passed truthy, must perform server.start()
  // default is falsey because constructor cannot return
  // a Promise, but start() can, if have to wait for server
  if (config.start) {
    this.start();
  }

}
Server.count = 0;
// returns promise that resolves if server starts
Server.prototype.start = function() {
  return new Promise((resolve) => {
    this.server = net.createServer((socket) => {
      if (this.openMessage) {
        socket.write(this.openMessage);
      }
      // Server just echos back what it receives
      socket.pipe(socket);
    }).on('error', (err) => {
      // handle errors here
      console.error(`${this.toString()} error ${err}`);
    }).on('clientError', (err) => {
      // handle errors here
      console.error(`${this.toString()} clientError ${err}`);
    }).on('data', (data) => {
      this.totalCharactersReceived += data.length;
      this.messagesReceived++;
      this.lastReception = Date.now();
    }).on('end', () => {
      // handle errors here
      if (state.verbose) {
        console.log(`${this.toString()} client disconnected`);
      }
    });

    this.server.listen(this.port, this.host);
    if (state.verbose) {
      console.log(`Server ${this.toString()} listenting on ${this.port}`);
    }
    resolve(this);
  });
};
Server.prototype.close = function() {
  this.server.close((err) => {
    if (state.verbose) {
      console.log('Server ${this.toString()) closed');
    }
    if (state.report) {
      console.log(`Server messages received ${this.messagesReceived}`);
      console.log(`Server characters received ${this.totalCharactersReceived}`);
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

if (state.connections) {
  console.log('connections not implemented yet');
} else {
  if (state.servers) {
    for (let i = 0; i < state.servers; i++) {
      let server = new Server({
        name: `Server ${i + 1}`,
        host: state.host,
        port: state.port + i,
        openMessage: `Greetings from Server ${i + 1}`,
        start: !state.clients // if clients, then start below so we can use the promise
      });
      servers.push(server);
    }
    if (!!state.clients) {
      // create clients for each server, but not until AFTER they all start
      let promises = servers.map(s => {
        return s.start();
      });
      Promise.all(promises).then(() => {
        for (let i = 0; i < state.clients; i++) {
          let client = new Client({
            name: `Client ${i + 1}`,
            host: state.host,
            port: state.port + i,
            seed: String.fromCharCode(97 + i), // 'a', 'b', ...
            maxMessages: state.maxMessages || 0,
            connect: true
          });
          clients.push(client);
        }
      });
    }

  } else { // only clients
    // Create specified # of clients to connect to state.host at port state.post + i
    if (state.clients) {
      for (let i = 0; i < state.clients; i++) {
        let client = new Client({
          name: `Client ${i + 1}`,
          host: state.host,
          port: state.port + i,
          seed: String.fromCharCode(97 + i), // 'a', 'b', ...
          maxMessages: state.maxMessages || 0,
          connect: false
        });
        clients.push(client);
        client.connect().then((client) => {
          if (state.verbose) {
            console.log(`${client.toString()} connection started`);
          }
        });
      }
    }
  }
}