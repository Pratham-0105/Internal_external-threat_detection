import { io } from 'socket.io-client';
import { NIDS_BASE_URL } from './apiClient';

class SocketService {
  constructor() {
    this.socket = null;
    this.listeners = new Map();
    this.isConnected = false;
  }

  connect() {
    if (this.socket) return this.socket;

    this.socket = io(NIDS_BASE_URL, {
      transports: ['websocket', 'polling'],
      reconnectionAttempts: 5,
      reconnectionDelay: 2000
    });

    this.socket.on('connect', () => {
      this.isConnected = true;
      console.log('Connected to CASOC NIDS Telemetry Socket.IO stream.');
      this._emit('connection_change', true);
    });

    this.socket.on('disconnect', () => {
      this.isConnected = false;
      console.log('Disconnected from CASOC NIDS Socket.IO stream.');
      this._emit('connection_change', false);
    });

    this.socket.on('new_threat_event', (data) => {
      this._emit('new_threat_event', data);
    });

    return this.socket;
  }

  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
      this.isConnected = false;
    }
  }

  subscribe(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event).add(callback);

    // Return unsubscribe function
    return () => {
      const set = this.listeners.get(event);
      if (set) {
        set.delete(callback);
      }
    };
  }

  _emit(event, data) {
    const set = this.listeners.get(event);
    if (set) {
      set.forEach((cb) => cb(data));
    }
  }
}

export const socketService = new SocketService();
