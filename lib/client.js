// Clients can connect to servers on this VM, or
// can connect to servers on other VMs
function Client(state) {

  this.state = state;

  ++Client.count;
  this.id = Client.count;
  this.name = config.name || `Client ${this.id}`;
  this.hostName = config.hostName;
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
    this.client.connect(this.port, this.hostName, () => {
      if (state.verbose) {
        logger.info(`Client ${this.toString()} connected`);
      }
      this.startWriteMessages();
      resolve(this);
    }).on('data', (data) => {
      if (state.verbose) {
        logger.info(`Client ${this.name} received: ${data}`);
      }
    }).on('close', () => {
      logger.info(`Client ${this.toString()} connection closed`);
      if (state.report) {
        logger.info(`messages sent: ${this.messageCount}`);
        logger.info(`total characters sent: ${this.totalCharactersSent}`)
      }
    }).on('error', (err) => {
      logger.error(`Client ${this.name} connection error: ${err}`);
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
    logger.info(`Client reached max message threshold of ${this.maxMessages}`);
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

exports = Client;
