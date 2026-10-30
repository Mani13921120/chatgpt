"""Time-bounded folder face verification, independent of webcam frame delivery."""
from dataclasses import dataclass, field
import math
import time

FOLDER_AUTH_SECONDS = 3.0


@dataclass
class FolderFaceAttempt:
    started: float = field(default_factory=time.monotonic)
    matches: int = 0
    required_matches: int = 5

    def expired(self, now=None):
        now = time.monotonic() if now is None else now
        return now - self.started >= FOLDER_AUTH_SECONDS

    def observe(self, similarity, threshold, now=None):
        if self.expired(now):
            return False
        if math.isfinite(similarity) and similarity >= threshold:
            self.matches += 1
        else:
            self.matches = 0
        return self.matches >= self.required_matches

    def no_face(self):
        self.matches = 0
