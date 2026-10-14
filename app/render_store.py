"""The "as delivered" views, kept on disk.

The inbox loader lays out every unread email in the background, and a mailbox of
a few thousand newsletters does not fit in the process: a single layout with its
inline images is anywhere from a few kilobytes to a megabyte, and the in-memory
cache in thephish_app holds sixty. So layouts are written here, under the data
volume, and survive a restart as well — a rebuild does not cost the mailbox a
second pass.

Three rules, each one there because breaking it shows the analyst the wrong
thing rather than failing:

* **An entry is stamped with the arrival time of the listing entry it was built
  from.** IMAP ids are sequence numbers and are reused as the mailbox changes; a
  stored layout whose stamp no longer matches belongs to another message, and it
  is deleted, not served. Same guard record_listing applies to cached bodies.
* **A layout with its remote images is never replaced by one without.** The
  background pass renders without touching the network (a remote image fetched
  for an email nobody opened tells its sender the mailbox is read); a click
  fetches them. The click's version is the better one and it stays.
* **A write never leaves half a record.** The metadata file is what makes an
  entry exist. It is removed before the payload is replaced and written after,
  both through a temporary file and a rename, so a process killed in between
  leaves an orphan the next start deletes — never an old stamp sitting on top of
  a new message's layout.

No eventlet, no libmagic: this is importable, and tested, outside the image.
"""

import hashlib
import io
import json
import os
import time

# Disk budget for every stored layout together. The count is not bounded on its
# own because it is not what varies: a plain-text email and a newsletter with a
# full-width header differ by two orders of magnitude in size, not in number.
MAX_BYTES = 1024 * 1024 * 1024

PAYLOAD_SUFFIX = '.json'
META_SUFFIX = '.meta.json'
TEMP_SUFFIX = '.tmp'


class RenderStore:

	def __init__(self, directory, max_bytes = MAX_BYTES):
		self.directory = directory
		self.max_bytes = max_bytes
		# uid -> metadata. Held in memory so that answering "is this one ready"
		# for every row of every push never touches the disk
		self.index = {}
		self._sequence = 0
		os.makedirs(directory, exist_ok = True)
		self._load_index()

	# ---- reading -------------------------------------------------------------

	def status(self, mail_uid, received_at):
		"""'full', 'layout' or None — from the index alone, without reading a file."""
		meta = self.index.get(str(mail_uid))
		if meta is None or meta.get('receivedAt') != received_at:
			return None
		return 'layout' if meta.get('layoutOnly') else 'full'

	def get(self, mail_uid, received_at):
		"""(payload, layout_only), or (None, None) when there is nothing valid."""
		mail_uid = str(mail_uid)
		meta = self.index.get(mail_uid)
		if meta is None:
			return None, None
		if meta.get('receivedAt') != received_at:
			# The id now names another message
			self.discard(mail_uid)
			return None, None
		try:
			with io.open(self._payload_path(meta['key']), encoding = 'utf-8') as handle:
				payload = json.load(handle)
		except (OSError, ValueError):
			self.discard(mail_uid)
			return None, None
		return payload, bool(meta.get('layoutOnly'))

	def total_bytes(self):
		return sum(meta.get('bytes', 0) for meta in self.index.values())

	# ---- writing -------------------------------------------------------------

	def put(self, mail_uid, received_at, payload, layout_only):
		"""Store one layout. Returns False when an existing entry is better."""
		mail_uid = str(mail_uid)
		current = self.index.get(mail_uid)
		if (current is not None and layout_only and not current.get('layoutOnly')
				and current.get('receivedAt') == received_at):
			return False

		key = self._key(mail_uid)
		data = json.dumps(payload, ensure_ascii = False).encode('utf-8')

		# Unpublish first: until the new metadata lands there is no entry at all,
		# rather than an old stamp describing a new payload
		self.index.pop(mail_uid, None)
		self._remove(self._meta_path(key))
		self._write(self._payload_path(key), data)

		self._sequence += 1
		meta = {
			'uid': mail_uid,
			'key': key,
			'receivedAt': received_at,
			'layoutOnly': bool(layout_only),
			'bytes': len(data),
			'stored': time.time(),
			'sequence': self._sequence
		}
		self._write(self._meta_path(key), json.dumps(meta).encode('utf-8'))
		self.index[mail_uid] = meta
		self._evict(keep = mail_uid)
		return True

	def discard(self, mail_uid):
		meta = self.index.pop(str(mail_uid), None)
		key = meta['key'] if meta else self._key(str(mail_uid))
		self._remove(self._meta_path(key))
		self._remove(self._payload_path(key))

	def retain(self, present):
		"""Keep only what the current listing still holds, under the same stamp.

		`present` maps mail UID to the arrival time the listing reports for it.
		"""
		for mail_uid, meta in list(self.index.items()):
			if mail_uid not in present or present[mail_uid] != meta.get('receivedAt'):
				self.discard(mail_uid)

	# ---- internals -----------------------------------------------------------

	def _evict(self, keep):
		# Oldest first, and never the entry that was just written: evicting the
		# thing somebody asked for in order to make room for it is not a cache
		while self.total_bytes() > self.max_bytes:
			candidates = [meta for uid, meta in self.index.items() if uid != keep]
			if not candidates:
				return
			oldest = min(candidates, key = lambda meta: meta.get('sequence', 0))
			self.discard(oldest['uid'])

	def _load_index(self):
		try:
			names = os.listdir(self.directory)
		except OSError:
			return
		keys_with_meta = set()
		for name in names:
			path = os.path.join(self.directory, name)
			if name.endswith(TEMP_SUFFIX):
				# A write that never reached its rename
				self._remove(path)
				continue
			if not name.endswith(META_SUFFIX):
				continue
			key = name[:-len(META_SUFFIX)]
			try:
				with io.open(path, encoding = 'utf-8') as handle:
					meta = json.load(handle)
			except (OSError, ValueError):
				self._remove(path)
				continue
			if (not isinstance(meta, dict) or meta.get('key') != key or not meta.get('uid')
					or not os.path.isfile(self._payload_path(key))):
				self._remove(path)
				continue
			keys_with_meta.add(key)
			self.index[meta['uid']] = meta
			self._sequence = max(self._sequence, int(meta.get('sequence') or 0))
		# A payload whose metadata never landed was never an entry
		for name in names:
			if name.endswith(PAYLOAD_SUFFIX) and not name.endswith(META_SUFFIX):
				if name[:-len(PAYLOAD_SUFFIX)] not in keys_with_meta:
					self._remove(os.path.join(self.directory, name))

	def _key(self, mail_uid):
		# Hashed because a Graph message id is long and carries characters a file
		# name should not, and because nothing about the name should be readable
		return hashlib.sha256(mail_uid.encode('utf-8')).hexdigest()[:40]

	def _payload_path(self, key):
		return os.path.join(self.directory, key + PAYLOAD_SUFFIX)

	def _meta_path(self, key):
		return os.path.join(self.directory, key + META_SUFFIX)

	def _write(self, path, data):
		temporary = path + TEMP_SUFFIX
		with io.open(temporary, 'wb') as handle:
			handle.write(data)
		os.replace(temporary, path)

	def _remove(self, path):
		try:
			os.remove(path)
		except OSError:
			pass
