import os
import sqlite3
import threading
import hashlib
from contextlib import contextmanager
from typing import Optional, List, Dict, Any

# [수정] 백그라운드 스레드에서 상대 경로를 잃어버리는 현상을 방지하기 위해 절대경로 강제
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DB_PATH = os.path.join(BASE_DIR, "trace_data.sqlite")

# ─────────────────────────────────────────────
# [T5] Thread-local connection pool + WAL mode
# ─────────────────────────────────────────────
_thread_local = threading.local()


@contextmanager
def get_db_connection(db_path: str = DB_PATH):
    """
    [T5] 커넥션 풀링: 스레드별 커넥션을 재사용하여 연결 오버헤드 제거.
    WAL 모드 활성화로 동시 읽기/쓰기 처리량 향상.
    """
    if not hasattr(_thread_local, "conns"):
        _thread_local.conns = {}

    conn = _thread_local.conns.get(db_path)
    is_new = conn is None

    if is_new:
        conn = sqlite3.connect(db_path, timeout=60.0, check_same_thread=False)
        # 쿼리 결과를 딕셔너리 형태로 접근할 수 있도록 설정
        conn.row_factory = sqlite3.Row
        # WAL 모드: 동시 읽기를 블로킹하지 않음
        conn.execute("PRAGMA journal_mode=WAL;")
        # 바쁜 대기 시간 60초로 확장하여 'database is locked' 예방
        conn.execute("PRAGMA busy_timeout=60000;")
        # 성능-내구성 균형
        conn.execute("PRAGMA synchronous=NORMAL;")
        # 64MB 페이지 캐시
        conn.execute("PRAGMA cache_size=-65536;")
        # FK 제약 활성화
        conn.execute("PRAGMA foreign_keys=ON;")
        _thread_local.conns[db_path] = conn

    try:
        yield conn
    except Exception:
        conn.rollback()
        if is_new:
            _thread_local.conns.pop(db_path, None)
            conn.close()
        raise


class TraceDBManager:
    """
    [T5] SQLite DB 관리자 — WAL 모드 + 스레드-로컬 커넥션 풀링 적용.
    [T7] 트레이스/코너케이스/뮤턴트 INSERT + 무결성 예외 처리 포함.
    """

    def __init__(self, db_path: str = DB_PATH) -> None:
        self.db_path = db_path
        self.init_db()

    def init_db(self) -> None:
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()

            # 1. TargetProgram
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS TargetProgram (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    original_code TEXT NOT NULL,
                    binary_path TEXT,
                    afl_binary_path TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # 2. DynamicTrace — (program_id, input_hash) UNIQUE 로 중복 방지 (T6)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS DynamicTrace (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    program_id INTEGER NOT NULL,
                    input_hash TEXT NOT NULL,
                    raw_input BLOB,
                    source TEXT CHECK(source IN ('afl_queue','afl_crash','afl_hang')),
                    execution_path TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(program_id) REFERENCES TargetProgram(id) ON DELETE CASCADE,
                    UNIQUE(program_id, input_hash)
                )
            ''')

            # 3. CornerCaseNode — 유동적인 코너 케이스 탐지 지원을 위해 CHECK 제약 제거
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS CornerCaseNode (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    trace_id INTEGER NOT NULL,
                    node_type TEXT,
                    exec_frequency REAL,
                    code_location TEXT,
                    FOREIGN KEY(trace_id) REFERENCES DynamicTrace(id) ON DELETE CASCADE
                )
            ''')

            # 4. SMTConstraint — is_solved=1 이면 trigger_input 필수
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS SMTConstraint (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    node_id INTEGER NOT NULL,
                    constraint_expr TEXT,
                    is_solved BOOLEAN DEFAULT 0,
                    trigger_input TEXT,
                    CHECK (is_solved = 0 OR
                           (is_solved = 1 AND trigger_input IS NOT NULL AND trigger_input != '')),
                    FOREIGN KEY(node_id) REFERENCES CornerCaseNode(id) ON DELETE CASCADE
                )
            ''')

            # 5. MutantRecord — 검증 결과 컬럼 포함 (T12)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS MutantRecord (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    program_id INTEGER NOT NULL,
                    node_id INTEGER,
                    injected_pattern_id INTEGER CHECK(injected_pattern_id BETWEEN 1 AND 6),
                    mutated_code TEXT NOT NULL,
                    mutant_binary_path TEXT,
                    survival_rate REAL,
                    llm_score REAL,
                    llm_rationale TEXT,
                    validated_at TIMESTAMP,
                    FOREIGN KEY(program_id) REFERENCES TargetProgram(id),
                    FOREIGN KEY(node_id) REFERENCES CornerCaseNode(id)
                )
            ''')

            # 6. DependencyCache (빌드 바이너리 캐시 트래커)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS DependencyCache (
                    repo_url TEXT PRIMARY KEY,
                    cache_key TEXT NOT NULL,
                    cache_dir TEXT NOT NULL,
                    linker_flags TEXT,
                    apt_packages TEXT,
                    last_built_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            conn.commit()

    # ─────────────────────────────────────────────
    # [T6, T7] 트레이스 적재 — MD5 해시 중복 제거
    # ─────────────────────────────────────────────
    def insert_trace(self, program_id: int, raw_input: bytes, source: str, execution_path: Optional[str] = None) -> Optional[int]:
        """중복 입력을 MD5 해시로 필터링 후 DynamicTrace에 INSERT. 이미 존재하면 기존 ID 리턴."""
        input_hash = hashlib.md5(raw_input).hexdigest()
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "INSERT INTO DynamicTrace (program_id, input_hash, raw_input, source, execution_path) VALUES (?,?,?,?,?)",
                    (program_id, input_hash, raw_input, source, execution_path)
                )
                conn.commit()
                return cursor.lastrowid
            except sqlite3.IntegrityError:
                # UNIQUE 제약 위반 시, 이미 존재하는 동일 program_id & input_hash의 ID 조회 후 반환
                cursor.execute(
                    "SELECT id FROM DynamicTrace WHERE program_id = ? AND input_hash = ?",
                    (program_id, input_hash)
                )
                row = cursor.fetchone()
                if row:
                    return row[0]
                return None

    # ─────────────────────────────────────────────
    # [T9] 코너 케이스 INSERT
    # ─────────────────────────────────────────────
    def insert_corner_case(self, trace_id: int, node_type: str,
                           exec_frequency: float, code_location: str = "") -> int:
        """exec_frequency < 0.01 조건은 DB CHECK 제약이 1차 방어선."""
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO CornerCaseNode (trace_id, node_type, exec_frequency, code_location) VALUES (?,?,?,?)",
                (trace_id, node_type, exec_frequency, code_location)
            )
            conn.commit()
            return cursor.lastrowid

    # ─────────────────────────────────────────────
    # [T7] 뮤턴트 INSERT — 무결성 검사
    # ─────────────────────────────────────────────
    def insert_mutant(self, program_id: int, node_id: Optional[int], pattern_id: int,
                      original_code: str, mutated_code: str,
                      mutant_binary_path: str = "") -> int:
        """
        Integrity Rule 1: original == mutated 이면 ValueError.
        Integrity Rule 2: pattern_id 1~6 범위는 DB CHECK가 강제.
        """
        if original_code.strip() == mutated_code.strip():
            raise ValueError("Integrity Rule 1 Failed: mutated_code is identical to original_code.")
        with get_db_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO MutantRecord (program_id, node_id, injected_pattern_id, mutated_code, mutant_binary_path) VALUES (?,?,?,?,?)",
                (program_id, node_id, pattern_id, mutated_code, mutant_binary_path)
            )
            conn.commit()
            return cursor.lastrowid

    # ─────────────────────────────────────────────
    # [T12] 검증 결과 업데이트
    # ─────────────────────────────────────────────
    def update_mutant_validation(self, mutant_id: int, survival_rate: float,
                                 llm_score: Optional[float],
                                 llm_rationale: Optional[str]) -> None:
        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """UPDATE MutantRecord
                   SET survival_rate=?, llm_score=?, llm_rationale=?, validated_at=CURRENT_TIMESTAMP
                   WHERE id=?""",
                (survival_rate, llm_score, llm_rationale, mutant_id)
            )
            conn.commit()

    # ─────────────────────────────────────────────
    # 조회 헬퍼
    # ─────────────────────────────────────────────
    def get_program(self, program_id: int) -> Optional[Dict]:
        with get_db_connection(self.db_path) as conn:
            row = conn.execute("SELECT * FROM TargetProgram WHERE id=?", (program_id,)).fetchone()
            return dict(row) if row else None

    def get_dependency_cache(self, repo_url: str) -> Optional[Dict]:
        with get_db_connection(self.db_path) as conn:
            row = conn.execute("SELECT * FROM DependencyCache WHERE repo_url=?", (repo_url,)).fetchone()
            return dict(row) if row else None

    def insert_or_update_dependency_cache(self, repo_url: str, cache_key: str, cache_dir: str, 
                                          linker_flags: str, apt_packages: str) -> None:
        with get_db_connection(self.db_path) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO DependencyCache 
                   (repo_url, cache_key, cache_dir, linker_flags, apt_packages, last_built_at) 
                   VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
                (repo_url, cache_key, cache_dir, linker_flags, apt_packages)
            )
            conn.commit()

    def get_mutant(self, mutant_id: int) -> Optional[Dict]:
        with get_db_connection(self.db_path) as conn:
            row = conn.execute("SELECT * FROM MutantRecord WHERE id=?", (mutant_id,)).fetchone()
            return dict(row) if row else None

    def get_trace_count(self, program_id: int) -> int:
        with get_db_connection(self.db_path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM DynamicTrace WHERE program_id=?", (program_id,)).fetchone()
            return row[0] if row else 0

    def get_trace_stats(self, program_id: int) -> dict:
        total = self.get_trace_count(program_id)
        return {"total": total}
