"""
Entry point for running the Flask application with SocketIO server.
"""
from app import create_app, socketio

app = create_app()

import os
import sys
import time

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    try:
        print(f"[*] Starting NIDS ML API Engine on port {port}...")
        socketio.run(app, debug=False, host='0.0.0.0', port=port, allow_unsafe_werkzeug=True)
    except OSError as e:
        if getattr(e, 'errno', None) == 48 and port == 5000:
            print(f"[!] Port 5000 is occupied by macOS AirPlay. Auto-switching NIDS ML API to Port 5005...")
            socketio.run(app, debug=False, host='0.0.0.0', port=5005, allow_unsafe_werkzeug=True)
        else:
            raise