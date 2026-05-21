-- Red-Team Policy Analyzer Database Schema
-- Tracks adversarial prompts, attack vectors, policy rules,
-- model responses, safety classifications, and gold sets.

PRAGMA foreign_keys = ON;

-- ── Harm Categories ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS harm_categories (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT    NOT NULL UNIQUE,
    description    TEXT,
    severity_level TEXT    NOT NULL CHECK(severity_level IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── Attack Vectors ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS attack_vectors (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    harm_category_id INTEGER NOT NULL REFERENCES harm_categories(id) ON DELETE CASCADE,
    name             TEXT    NOT NULL,
    description      TEXT,
    framing_type     TEXT,
    created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── Policy Rules ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS policy_rules (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    harm_category_id INTEGER REFERENCES harm_categories(id) ON DELETE SET NULL,
    rule_text        TEXT NOT NULL,
    domain           TEXT,
    created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── Prompts (base + variations) ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS prompts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_vector_id INTEGER REFERENCES attack_vectors(id) ON DELETE SET NULL,
    text             TEXT    NOT NULL,
    is_base          INTEGER NOT NULL DEFAULT 1 CHECK(is_base IN (0,1)),
    parent_prompt_id INTEGER REFERENCES prompts(id) ON DELETE SET NULL,
    variation_type   TEXT,
    created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── Model Responses ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS model_responses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    prompt_id   INTEGER NOT NULL REFERENCES prompts(id) ON DELETE CASCADE,
    response_text TEXT,
    model_name  TEXT,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── Safety Classifications ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS safety_classifications (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    prompt_id         INTEGER NOT NULL REFERENCES prompts(id) ON DELETE CASCADE,
    model_response_id INTEGER REFERENCES model_responses(id) ON DELETE SET NULL,
    classification    TEXT    NOT NULL CHECK(classification IN ('SAFE','UNSAFE','AMBIGUOUS')),
    confidence        REAL    NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
    classifier_type   TEXT    NOT NULL DEFAULT 'heuristic',
    reasoning         TEXT,
    created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── Policy Coverage Map ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS policy_coverage (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_vector_id INTEGER NOT NULL REFERENCES attack_vectors(id) ON DELETE CASCADE,
    policy_rule_id   INTEGER REFERENCES policy_rules(id) ON DELETE SET NULL,
    coverage_status  TEXT    NOT NULL CHECK(coverage_status IN ('COVERED','PARTIAL','GAP')),
    notes            TEXT,
    updated_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── Gold Set ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS gold_set (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    prompt_id               INTEGER NOT NULL REFERENCES prompts(id) ON DELETE CASCADE,
    expected_classification TEXT    NOT NULL CHECK(expected_classification IN ('SAFE','UNSAFE','AMBIGUOUS')),
    confidence_level        TEXT    NOT NULL CHECK(confidence_level IN ('HIGH','MEDIUM','LOW')),
    labeler_notes           TEXT,
    created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ── Indexes ───────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_prompts_attack_vector   ON prompts(attack_vector_id);
CREATE INDEX IF NOT EXISTS idx_prompts_parent          ON prompts(parent_prompt_id);
CREATE INDEX IF NOT EXISTS idx_prompts_is_base         ON prompts(is_base);
CREATE INDEX IF NOT EXISTS idx_classifications_prompt  ON safety_classifications(prompt_id);
CREATE INDEX IF NOT EXISTS idx_classifications_label   ON safety_classifications(classification);
CREATE INDEX IF NOT EXISTS idx_coverage_vector         ON policy_coverage(attack_vector_id);
CREATE INDEX IF NOT EXISTS idx_gold_set_prompt         ON gold_set(prompt_id);
