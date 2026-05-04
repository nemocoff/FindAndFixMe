import sqlite3
from typing import List, Dict, Any

class TraceDBManager:
    """
    SQLite DB Manager for trace data, mutations, and history.
    """
    def __init__(self, db_path: str = "trace_data.sqlite") -> None:
        self.db_path = db_path
        self.init_db()
        
    def init_db(self) -> None:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 1. TargetProgram
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS TargetProgram (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                original_code TEXT NOT NULL
            )
        ''')
        
        # 2. DynamicTrace
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS DynamicTrace (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                program_id INTEGER,
                execution_path TEXT,
                FOREIGN KEY(program_id) REFERENCES TargetProgram(id)
            )
        ''')
        
        # 3. CornerCaseNode
        # Rule 2: exec_frequency < 0.01
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS CornerCaseNode (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                trace_id INTEGER,
                node_type TEXT,
                exec_frequency REAL CHECK(exec_frequency < 0.01),
                FOREIGN KEY(trace_id) REFERENCES DynamicTrace(id)
            )
        ''')
        
        # 4. SMTConstraint
        # Rule 3: FK(node_id) 무효성 방지는 FOREIGN KEY 로 해결 (또는 Pragma 외래키 활성화)
        # Rule 5: is_solved가 True일 때 trigger_input의 NULL 혹은 빈 값 검사
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS SMTConstraint (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id INTEGER NOT NULL,
                constraint_expr TEXT,
                is_solved BOOLEAN,
                trigger_input TEXT,
                CHECK (is_solved = 0 OR (is_solved = 1 AND trigger_input IS NOT NULL AND trigger_input != '')),
                FOREIGN KEY(node_id) REFERENCES CornerCaseNode(id) ON DELETE CASCADE
            )
        ''')
        
        # 5. MutantRecord
        # Rule 1: original_code != mutated_code (handled in Python or trigger, but we can do simple column check if both in same table. Here we'll handle it in Python code)
        # Rule 4: injected_pattern_id 1~6
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS MutantRecord (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                program_id INTEGER,
                node_id INTEGER,
                injected_pattern_id INTEGER CHECK(injected_pattern_id BETWEEN 1 AND 6),
                mutated_code TEXT NOT NULL,
                FOREIGN KEY(program_id) REFERENCES TargetProgram(id),
                FOREIGN KEY(node_id) REFERENCES CornerCaseNode(id)
            )
        ''')
        
        conn.commit()
        conn.close()

    def insert_mutant(self, program_id: int, node_id: int, pattern_id: int, original_code: str, mutated_code: str):
        # Rule 1 validation in application logic
        if original_code == mutated_code:
            raise ValueError("Integrity Rule 1 Failed: original_code and mutated_code must not be identical.")
            
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO MutantRecord (program_id, node_id, injected_pattern_id, mutated_code)
            VALUES (?, ?, ?, ?)
        ''', (program_id, node_id, pattern_id, mutated_code))
        conn.commit()
        conn.close()
