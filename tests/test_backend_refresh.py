from __future__ import annotations

from icloud_ftp.backend import ICloudPyBackend


class Node:
    def __init__(self, drive, name="root", node_type="folder", size=0):
        self.drive = drive
        self.data = {"name": name, "type": node_type, "drivewsid": name, "size": size}
        self._children = None

    @property
    def name(self):
        return self.data["name"]

    @property
    def type(self):
        return self.data["type"]

    @property
    def size(self):
        return self.data["size"]

    date_modified = None
    date_changed = None
    date_created = None

    def get_children(self):
        if self._children is None:
            self._children = [Node(self.drive, name, "file", len(data)) for name, data in self.drive.files.items()]
        return self._children

    def __getitem__(self, name):
        for child in self.get_children():
            if child.name == name:
                return child
        raise KeyError(name)


class Drive:
    def __init__(self):
        self.files = {"old.txt": b"old"}
        self.root = Node(self)


class Service:
    def __init__(self):
        self.drive = Drive()


def test_drive_cache_zero_reflects_web_deletion_on_next_list():
    service = Service()
    backend = ICloudPyBackend(service, cache_seconds=0)
    assert [entry.name for entry in backend.list("/")] == ["old.txt"]
    service.drive.files.clear()  # Represents deletion in iCloud Web.
    assert backend.list("/") == []

