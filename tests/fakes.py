from __future__ import annotations

from pathlib import Path, PurePosixPath

from icloud_ftp.backend import Entry


class FakeBackend:
    def __init__(self):
        self.files = {"/hello.txt": b"hello"}
        self.dirs = {"/"}

    @staticmethod
    def norm(path):
        result = "/" + str(PurePosixPath(path)).lstrip("/")
        return "/" if result == "/." else result

    def list(self, path):
        path = self.norm(path)
        if path not in self.dirs:
            raise KeyError(path)
        rows = []
        for directory in self.dirs:
            if directory != path and str(PurePosixPath(directory).parent) == path:
                rows.append(Entry(PurePosixPath(directory).name, True, 0, 1))
        for filename, data in self.files.items():
            if str(PurePosixPath(filename).parent) == path:
                rows.append(Entry(PurePosixPath(filename).name, False, len(data), 1))
        return rows

    def stat(self, path):
        path = self.norm(path)
        if path in self.dirs:
            return Entry(PurePosixPath(path).name or "/", True, 0, 1)
        if path in self.files:
            return Entry(PurePosixPath(path).name, False, len(self.files[path]), 1)
        raise KeyError(path)

    def download(self, path, destination):
        destination.write(self.files[self.norm(path)])
        destination.seek(0)

    def upload(self, path, source: Path):
        self.files[self.norm(path)] = source.read_bytes()

    def mkdir(self, path):
        path = self.norm(path)
        if path in self.dirs:
            raise FileExistsError(path)
        if self.norm(str(PurePosixPath(path).parent)) not in self.dirs:
            raise FileNotFoundError(path)
        self.dirs.add(path)

    def delete(self, path, *, directory):
        path = self.norm(path)
        if directory:
            children = set(self.files) | self.dirs
            children.discard(path)
            if any(str(PurePosixPath(item).parent) == path for item in children):
                raise OSError("directory is not empty")
            self.dirs.remove(path)
        else:
            del self.files[path]

    def rename(self, source, destination):
        source, destination = self.norm(source), self.norm(destination)
        if source in self.files:
            self.files[destination] = self.files.pop(source)
        else:
            self.dirs.remove(source)
            self.dirs.add(destination)
