"""
Reasoning Dump Storage - Structured persistence of LLM conversation histories
for Scanner_Union's unit-level and path-level analysis.

Directory layout under base_dir:
  units/
    backward/<cache_key[:16]>.json
    intermediate/<cache_key[:16]>.json
    forward/<cache_key[:16]>.json
  paths/
    <path_id_sanitized>.json
  index.json
"""
import os
import json
import logging
import re
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


def _sanitize_filename(name: str) -> str:
    """Sanitize a string for use as a filename."""
    return re.sub(r'[^\w\-.]', '_', str(name))


class ReasoningDumpStorage:
    """Stores structured reasoning dumps (conversation histories + results)
    for each Logic Unit and assembled vulnerability path."""

    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.units_dir = os.path.join(base_dir, 'units')
        self.paths_dir = os.path.join(base_dir, 'paths')

        # Create directory structure
        for segment_type in ('backward', 'intermediate', 'forward'):
            os.makedirs(os.path.join(self.units_dir, segment_type), exist_ok=True)
        os.makedirs(self.paths_dir, exist_ok=True)

        # Track what we've stored for index generation
        self._unit_files: Dict[str, str] = {}  # cache_key -> relative file path
        self._stored_count = {'backward': 0, 'intermediate': 0, 'forward': 0, 'paths': 0}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Unit-level storage
    # ------------------------------------------------------------------

    def store_unit_reasoning(
        self,
        cache_key: str,
        segment_type: str,
        conversation_history: List[Dict],
        analysis_result: Optional[Dict] = None,
        metadata: Optional[Dict] = None
    ):
        """Store the full conversation history and result for a single Logic Unit.

        Args:
            cache_key: The unit's cache key (full hash).
            segment_type: 'backward', 'intermediate', or 'forward'.
            conversation_history: List of message dicts (role, content, tool_calls, ...).
            analysis_result: The parsed analysis result dict.
            metadata: Optional extra metadata (variable_name, steps_count, paths_using, context, ...).
        """
        if not conversation_history:
            logger.debug(f"Skipping dump for {segment_type} unit {cache_key[:16]} — empty conversation")
            return

        short_key = cache_key[:16]
        rel_path = os.path.join('units', segment_type, f'{short_key}.json')
        abs_path = os.path.join(self.base_dir, rel_path)

        dump = {
            'cache_key': cache_key,
            'segment_type': segment_type,
            'timestamp': datetime.now().isoformat(),
            'metadata': metadata or {},
            'conversation_history': conversation_history,
            'analysis_result': analysis_result,
        }

        try:
            with open(abs_path, 'w', encoding='utf-8') as f:
                json.dump(dump, f, indent=2, ensure_ascii=False, default=str)
            with self._lock:
                self._unit_files[cache_key] = rel_path
                self._stored_count[segment_type] = self._stored_count.get(segment_type, 0) + 1
            logger.debug(f"Stored reasoning dump for {segment_type} unit {short_key}")
        except Exception as e:
            logger.warning(f"Failed to write reasoning dump {abs_path}: {e}")

    # ------------------------------------------------------------------
    # Path-level (vulnerability) storage
    # ------------------------------------------------------------------

    def store_path_reasoning(
        self,
        path_id: str,
        backward_key: Optional[str],
        intermediate_key: Optional[str],
        forward_key: Optional[str],
        units: Dict[str, Any]
    ):
        """Assemble a B->I->F reasoning chain for one vulnerability path.

        Reads the conversation_history from each referenced LogicUnit (if still
        available on the unit object) or from the already-written unit JSON files.

        Args:
            path_id: The path identifier.
            backward_key: Cache key of the backward unit (may be None).
            intermediate_key: Cache key of the intermediate unit (may be None).
            forward_key: Cache key of the forward unit (may be None).
            units: Dict of cache_key -> LogicUnit with conversation_history / analysis_result.
        """
        sanitized = _sanitize_filename(path_id)
        abs_path = os.path.join(self.paths_dir, f'{sanitized}.json')

        reasoning_chain = []

        for phase, key in [('backward', backward_key),
                           ('intermediate', intermediate_key),
                           ('forward', forward_key)]:
            if not key:
                continue

            entry: Dict[str, Any] = {
                'phase': phase,
                'cache_key': key,
                'conversation_history': [],
                'result': None,
            }

            unit = units.get(key)
            if unit:
                entry['conversation_history'] = getattr(unit, 'conversation_history', []) or []
                # Use 'is not None' to avoid treating empty dict {} as falsy
                ar = getattr(unit, 'analysis_result', None)
                entry['result'] = ar if ar is not None else getattr(unit, 'cached_result', None)

                # For intermediate units, filter context_results to the
                # specific (backward_key, forward_key) pair for this path.
                if phase == 'intermediate' and isinstance(entry['result'], dict):
                    ctx_all = entry['result'].get('context_results', [])
                    matched = [
                        ctx for ctx in ctx_all
                        if ctx.get('backward_key') == backward_key
                        and ctx.get('forward_key') == forward_key
                    ]
                    entry['result'] = {
                        **entry['result'],
                        'context_results': matched,
                        'contexts_analyzed': len(matched),
                    }

            # Fallback: try reading from the unit JSON file if conversation is empty
            if not entry['conversation_history']:
                entry['conversation_history'] = self._load_unit_conversation(key, phase)

            reasoning_chain.append(entry)

        dump = {
            'path_id': path_id,
            'connection': {
                'backward_key': backward_key,
                'intermediate_key': intermediate_key,
                'forward_key': forward_key,
            },
            'timestamp': datetime.now().isoformat(),
            'reasoning_chain': reasoning_chain,
        }

        try:
            with open(abs_path, 'w', encoding='utf-8') as f:
                json.dump(dump, f, indent=2, ensure_ascii=False, default=str)
            self._stored_count['paths'] += 1
            logger.debug(f"Stored path reasoning dump for {path_id}")
        except Exception as e:
            logger.warning(f"Failed to write path reasoning dump {abs_path}: {e}")

    # ------------------------------------------------------------------
    # Index
    # ------------------------------------------------------------------

    def write_index(self, units: Dict[str, Any], connections: Any):
        """Write an index.json summarising all stored reasoning dumps.

        Args:
            units: Dict of cache_key -> LogicUnit.
            connections: LogicUnitConnections instance.
        """
        index: Dict[str, Any] = {
            'timestamp': datetime.now().isoformat(),
            'stored_counts': dict(self._stored_count),
            'unit_index': {},
            'connection_stats': {},
        }

        # Build unit index
        for cache_key, rel_path in self._unit_files.items():
            unit = units.get(cache_key)
            index['unit_index'][cache_key] = {
                'file': rel_path,
                'segment_type': unit.segment_type if unit else 'unknown',
                'paths_using': list(unit.paths_using) if unit else [],
            }

        # Connection stats
        if hasattr(connections, 'get_connection_statistics'):
            index['connection_stats'] = connections.get_connection_statistics()

        abs_path = os.path.join(self.base_dir, 'index.json')
        try:
            with open(abs_path, 'w', encoding='utf-8') as f:
                json.dump(index, f, indent=2, ensure_ascii=False, default=str)
            logger.info(f"Wrote reasoning dump index to {abs_path} "
                        f"({len(self._unit_files)} units, {self._stored_count['paths']} paths)")
        except Exception as e:
            logger.warning(f"Failed to write index {abs_path}: {e}")

    # ------------------------------------------------------------------
    # Decomposition log
    # ------------------------------------------------------------------

    def dump_decomposition_log(self, decompositions: Dict[str, Any]):
        """Write a human-readable decomposition log showing how each path
        was split into backward / intermediate / forward segments.

        Output: ``base_dir/decomposition_log.txt``

        Args:
            decompositions: Dict of path_id -> PathDecomposition.
        """
        abs_path = os.path.join(self.base_dir, 'decomposition_log.txt')

        def _fmt_step(step, idx, relationship=None) -> str:
            fp = step.fromPoint
            tp = step.toPoint
            rel = f"  [{relationship}]" if relationship else ""
            same = "SAME" if step.sameFunction else "CROSS"
            return (f"    [{idx}] {fp.functionName}:{fp.line} ({fp.variable}) "
                    f"-> {tp.functionName}:{tp.line} ({tp.variable})  "
                    f"{same}{rel}")

        try:
            with open(abs_path, 'w', encoding='utf-8') as f:
                f.write(f"Path Decomposition Log  ({len(decompositions)} paths)\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                f.write("=" * 80 + "\n\n")

                for path_id in sorted(decompositions.keys(),
                                      key=lambda p: int(p.split('_')[-1])
                                      if p.split('_')[-1].isdigit() else p):
                    decomp = decompositions[path_id]
                    f.write(f"--- {path_id} ---\n")

                    for seg_name, steps, cache_key, is_virtual in [
                        ('BACKWARD',     decomp.backward_steps,
                         decomp.backward_cache_key,     decomp.backward_is_virtual),
                        ('INTERMEDIATE', decomp.intermediate_steps,
                         decomp.intermediate_cache_key,  False),
                        ('FORWARD',      decomp.forward_steps,
                         decomp.forward_cache_key,       decomp.forward_is_virtual),
                    ]:
                        if not steps and not cache_key:
                            continue
                        virt_tag = " [VIRTUAL]" if is_virtual else ""
                        f.write(f"  {seg_name}{virt_tag}  "
                                f"({len(steps)} steps)  "
                                f"key={cache_key[:40] if cache_key else 'None'}...\n")
                        for i, step in enumerate(steps):
                            key = (step.fromPoint.file, step.fromPoint.line,
                                   step.toPoint.file, step.toPoint.line,
                                   step.flowstep)
                            rel = decomp.steps_relationships.get(key)
                            f.write(_fmt_step(step, i, rel) + "\n")

                    f.write("\n")

            logger.info(f"Wrote decomposition log to {abs_path} "
                        f"({len(decompositions)} paths)")
        except Exception as e:
            logger.warning(f"Failed to write decomposition log {abs_path}: {e}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _load_unit_conversation(self, cache_key: str, segment_type: str) -> List[Dict]:
        """Try to load conversation_history from an already-written unit JSON."""
        short_key = cache_key[:16]
        abs_path = os.path.join(self.units_dir, segment_type, f'{short_key}.json')
        if not os.path.exists(abs_path):
            return []
        try:
            with open(abs_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return data.get('conversation_history', [])
        except Exception:
            return []
