# Class used for logging with different levels of severity
# The constructor takes the socketio object and the socket id of the client to
# send logs to or, when there is no requesting client, a room to send them to.
# The target is never empty: in python-socketio `to=None` (and `to=''`) means
# broadcast to every connected socket, and the log carries observables,
# subjects and reporter addresses. Without a target the log is dropped
class WebSocketLogger:

	def __init__(self, socketio, sid, room = None):
		self.socketio = socketio
		self.target = sid or room or None

	def _emit(self, event, message):
		if self.target:
			self.socketio.emit(event, message, to = self.target)

	def emit_info(self, message):
		self._emit("logInfo", message)

	def emit_warning(self, message):
		self._emit("logWarning", message)

	def emit_error(self, message):
		self._emit("logError", message)
