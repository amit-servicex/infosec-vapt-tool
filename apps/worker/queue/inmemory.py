from collections import deque
from typing import Optional, Any, Dict

class InMemoryQueue:
    def __init__(self):
        self._q = deque()

    def put(self, item: Dict[str, Any]):
        self._q.append(item)

    def get(self) -> Optional[Dict[str, Any]]:
        return self._q.popleft() if self._q else None

    def size(self) -> int:
        return len(self._q)
