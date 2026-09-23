# Sentinel AI

**A CLI-Based, LLM-Powered Static Analysis and Automated Code Remediation Tool**

Sentinel is a lightweight, command-line tool that uses an LLM to audit a local codebase for security vulnerabilities and logic bugs, and to propose safe, human-approved patches — without giving the model broad, unchecked access to your filesystem.

---

## Why Sentinel?

Most AI-assisted code-review tools either:
- require heavyweight infrastructure, or
- give the underlying language model too much unchecked control over the filesystem, or
- stop at detection without offering any repair path, or
- send proprietary source code to a remote model with no privacy-conscious handling.

Sentinel takes the opposite approach: a thin orchestration layer around a single, well-constrained LLM call, with the real engineering effort spent on safely gathering source code, forcing the model's output into a strict machine-actionable schema, and safely applying that output back to disk — only after explicit human confirmation.

## Features

- **Two analysis modes**
  - `audit` — the model acts as an adversarial security reviewer, scanning the codebase for vulnerabilities and rating their risk.
  - `repair` — the model acts as a compiler-style debugger, locating syntax and logic errors.
- **Safe ingestion** — a directory walker excludes credentials, vendored/generated folders (`.git`, `node_modules`, `__pycache__`, `build`, `dist`), lockfiles, and binary files before anything reaches the model.
- **Schema-validated output** — responses are constrained to a strict JSON schema via Pydantic models and Gemini's `response_schema`, instead of relying on fragile free-text or regex parsing.
- **Context-anchored patches** — proposed fixes are anchored by 2 lines of unchanged context above and below the change, avoiding the line-number drift of numeric diffs and the review cost of full-file rewrites.
- **Human-in-the-loop by design** — every LLM response is treated as untrusted input. No patch is ever applied without explicit human (y/n) confirmation.
- **Path-traversal guard** — patches are only ever written inside the verified project root.

## How It Works

```
Local Codebase / Input
        │
        ▼
Code Ingestion / Directory Walking
        │
        ▼
Exclusion Filtering (secrets, vendored code, binaries)
        │
        ▼
Prompt Assembly
        │
        ▼
Gemini API / LLM Analysis
        │
        ▼
Schema Validation
        │
        ▼
Report / Proposed Patch
        │
        ▼
Human Review / Confirmation
        │
        ▼
Safe Patch Application
```

## Requirements

- Python 3.x
- A stable internet connection (analysis runs via the Gemini API — no local model hosting or GPU required)
- Minimum 4 GB RAM (8 GB recommended)

## Setup

1. **Clone the repository:**

   ```
   git clone <your-repo-url>
   cd Sentinel
   ```

2. **Install dependencies:** Ensure Python is installed, then install the required packages (including the Gemini API dependencies):

   ```
   pip install -r requirements.txt
   ```

3. **Configure the API Key:**
   - Generate your API key from Google AI Studio.
   - Create a file named `.env` in the root project folder.
   - Add your key to the file using this exact format:

     ```
     GEN_KEY=your_api_key_here
     ```

4. **Configure the Executable:**
   - Open the `.bat` file provided in the repository.
   - Update the path inside the file to point to the exact location of the Sentinel script on your local machine.

5. **Set Environment Variables:**
   - Add the folder containing your configured `.bat` file to your system's `PATH` environment variable. This allows you to run the CLI globally from any directory.

6. **Run the Application:**
   - Open Command Prompt and initialize a scan:

     ```
     sentinel --path <Folder_path> --mode <Audit/Repair>
     ```
## Usage

```bash
# Audit a codebase for vulnerabilities
sentinel audit /path/to/project

# Locate and repair syntax/logic errors
sentinel repair /path/to/project
```

Sentinel will:
1. Walk the target directory and safely bundle the relevant source.
2. Send a structured prompt to the Gemini API.
3. Parse the schema-validated JSON response into a human-readable report.
4. Write the full report to disk, and, if patches are proposed, stage a review file.
5. Ask for explicit confirmation before applying any patch to your files.

## Safety Principles

- The system never writes outside the project root.
- The system never applies a patch without explicit user confirmation.
- Every LLM response is treated as untrusted input, not as a trusted instruction.
- Secrets and credential directories are excluded before anything is sent to the model.

## Roadmap

- Replace raw-text ingestion with AST-based structural parsing.
- Add a sandboxed execution environment to validate patches before they're offered for commit.
- Introduce automated patch validation (syntax checks / test execution) as a pass/fail gate.
- Add a backup-before-overwrite mechanism for fully reversible writes.
- Scale ingestion beyond the single-prompt design (chunking/RAG) for large repositories.
- Make the LLM backend provider-agnostic.

## Status

This is a working prototype centered on the trust-boundary design described above. It currently analyzes raw source text rather than an AST, and does not yet sandbox or auto-revalidate patches before staging — both are near-term hardening goals (see Roadmap).
Some bugs might be present, Full project will de posted soon
