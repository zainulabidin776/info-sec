import io from 'socket.io-client';

const SOCKET_URL = process.env.REACT_APP_SOCKET_URL || 'http://localhost:5000';

let socket = null;

export const connectSocket = (userId) => {
  if (socket?.connected) {
    return socket;
  }

  socket = io(SOCKET_URL, {
    transports: ['websocket', 'polling']
  });

  socket.on('connect', () => {
    console.log('Socket connected');
    socket.emit('join-room', userId);
  });

  socket.on('disconnect', () => {
    console.log('Socket disconnected');
  });

  return socket;
};

export const disconnectSocket = () => {
  if (socket) {
    socket.disconnect();
    socket = null;
  }
};

export const getSocket = () => {
  return socket;
};

export const sendMessageViaSocket = (messageData) => {
  if (socket && socket.connected) {
    socket.emit('send-message', messageData);
  }
};

export const onReceiveMessage = (callback) => {
  if (socket) {
    socket.on('receive-message', callback);
  }
};

export const offReceiveMessage = (callback) => {
  if (socket) {
    socket.off('receive-message', callback);
  }
};

