import os
import argparse
import sys
import json
from google import genai 
from google.genai import errors
from typing import Literal, Optional, List
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from pathlib import Path

target_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(target_env_path):
      load_dotenv(target_env_path)
else:
      print("Required File not found")

pii_key = os.environ.get("Gen_key")


class CodePatch(BaseModel):
    target_file: str = Field(description="The exact relative path of the file needing a fix (e.g., 'src/auth.js')")
    original_snippet: str = Field(description="The vulnerable lines of code exactly as they appear in the source with addition of 2 lines of unchanged code above the vulnerability and 2 lines of unchanged code below it")
    corrected_snippet: str = Field(description="The secure replacement code. It MUST preserve the exact same 2 upper and 2 lower unchanged context lines provided in original_snippet, cleanly wrapping your newly corrected secure code inside the middle.")



class SentinalReport(BaseModel):
       file_name: str = Field(description="The exact name of the dominant project directory or primary file analyzed.")

       language: str = Field(description="Comma-separated list of programming languages detected (e.g., 'JavaScript, HTML, Python').")

       complexity_score: Literal["Low", "Medium", "High"] = Field(description="Algorithmic and structural complexity rating of the scanned codebase.")

       summary: str = Field(description="Exactly one sentence summarizing the core objective and function of this codebase.")

       vulnerabilities_found: list[str] = Field(description="A list of distinct security flaws, configuration omissions, or logic bugs found. Return an empty list [] if the code is safe.")

       risk_level: Literal["SAFE", "WARNING", "CRITICAL"] = Field(description=(
             "The overall security posture. Must be CRITICAL if plain-text credentials or XSS exist, \n"
             "WARNING for missing validations, and SAFE only if zero flaws are found."
             ))
       Attacks: list[str] = Field(description=(
             "A list where each item follows the strict format: "'Attack Name: 1-line explanation of what is that vulnerability and how the vulnerability is weaponized. \n'
              " Return an empty list [] if zero vulnerabilities exist.")
       )
       Suggestion: str = Field(
        description=(
            "A strict 2-3 sentence technical recommendation block tailored directly to the codebase state:\n"
            "- PATH A (If vulnerabilities exist / risk_level is WARNING or CRITICAL): Provide exact, concrete code-level steps to patch the bugs and list secure alternative libraries.\n"
            "- PATH B (If the codebase is completely SAFE): Act as an expert product engineer and suggest 2-3 high-value advanced features, performance optimizations, or architectural expansions that would level up this specific project."
        )
    )
       
       is_vulnerable: bool = Field(description="Set to True if risk_level is WARNING or CRITICAL, False if SAFE.")
       patches: List[CodePatch] = Field(description="List of targeted code patches. Return empty list [] if is_vulnerable is False.")



def Directi_Walker(root_dictinory):
      bundle_Text = []
      ignor_folder = {'.git', 'node_modules', 'target', '__pycache__', 'dist', 'build', 'venv', '.vscode', '.idea', '.aws', '.azure', '.gcloud', '.ssh', 'secrets', 'credentials'}
      ignor_file = {'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'Cargo.lock', 'poetry.lock'}
      max_filesize = 350 * 1024

      print(f"Scan initiating on Directory: {root_dictinory}")

      for dirpath, _, filenames in os.walk(root_dictinory):
            if any(ignored in dirpath.split(os.sep) for ignored in ignor_folder):
                  continue
            for filename in filenames:
                if (
                    filename.startswith('.env') or
                    '.env' in filename or
                    filename.endswith('.lock') or
                    filename in ignor_file
                ):
                        continue
                # Redundant check removed
                full_path = os.path.join(dirpath,filename)
                rel_path = os.path.relpath(full_path, root_dictinory)
                try:
                      file_size = os.path.getsize(full_path)
                      if file_size > max_filesize:
                            src_say = f"--File path: {rel_path} --\n [sentinel warning: content ommited...]\n ---End of file"
                            bundle_Text.append(src_say)
                            print(f"Size is too large to handle, File name: {rel_path}")
                            continue
                      
                      with open(full_path,"r", encoding='utf-8' ) as Textt:
                        FileCopy=Textt.read(1024)
                        if '\0' in FileCopy:
                              continue
                        Textt.seek(0)
                        content = Textt.read()
                        print("File read success")

                        src_say = f"--- FILE PATH: {rel_path} ---\n{content}\n--- END OF FILE ---"
                        bundle_Text.append(src_say)
                        print(f"  -> Analyzed: {rel_path}")

                except UnicodeDecodeError:
                        continue
                except Exception as e:
                        print(f"FIle read unsuccesful: {e}")
                        continue

      return "\n\n".join(bundle_Text)
                        


def main():
      cmdexu = argparse.ArgumentParser(
            description="Sentinel AI: Automated Codebase Vulnerability and Architectural Scanner."
      )

      cmdexu.add_argument(
            "--path",
            type=str,
            required=True,
            help="The absolute path to the local project folder you want Sentinel to scan."
      )
      cmdexu.add_argument(
            "--mode",
            type=str,
            choices=["audit", "repair"],
            required=True,
            help="The mode in which you want Sentinel to workout."
      )
      args = cmdexu.parse_args()
      Spath = args.path
      Smode = args.mode 

      if not pii_key:
            print("Key code not found\n")
            print("Pls ensure Proper configuration")
            sys.exit(1)

      if not os.path.exists(Spath):
            print(f"The specified Directory not found: {Spath}")
            sys.exit(1)

      codebase = Directi_Walker(Spath)

      if not codebase.strip():
            print("Source folder not found")
            sys.exit(1)
      print("The code base have been featched succesfully....")

      print("Connecting to server.....")
      try:
            clint = genai.Client(api_key= pii_key)
            if Smode == "audit":
                  Prompt_push = (f"""
                        You are receiving the raw source code repository text bundle for evaluation.
                        Analyze the following codebase files for security vulnerabilities and match your findings directly to the requested JSON layout schema.

                        ======================================================================
                        CODEBASE EXPOSED SOURCE SOURCE:
                        ======================================================================
                        {codebase}
                        ======================================================================

                        EXECUTION ASSIGNMENT:
                        1. Scan every code block exposed above. Log all high-risk bugs in the 'vulnerabilities_found' array.
                        2. Formulate micro-targeted structural patches matching the exact dual-bounded context rules (2 lines above, 2 lines below) specified in your system instructions.
                        3. Output the finalized data payload in raw, valid JSON matching your schema format.
                        """
                  )
                  print("Analyzing Folder structure... Please wait.")

                  response = clint.models.generate_content(
                  model='gemini-2.5-flash',
                  contents=Prompt_push,
                  config={
                        'system_instruction': (
                              "You are Sentinel, a cynical, highly analytical adversarial security auditor and micro-focused patch engineer. "
                              "Your primary goal is to stress-test source files, identify logical weaknesses, unvalidated inputs, data exposure vectors, and architectural flaws. "
                              "You must output plain raw JSON matching the requested schema exactly, containing no conversational formatting tags.\n\n"
                              
                              "CRITICAL OUTPUT RULE FOR THE 'Suggestion' FIELD:\n"
                              "1. If you find vulnerabilities, dedicate the 'Suggestion' string entirely to explaining how the developer can fix them immediately.\n"
                              "2. If you find absolutely zero vulnerabilities and rate the project as SAFE, do not give generic praise. Instead, propose creative, useful, highly relevant features or scaling optimizations that fit the specific theme of the scanned project.\n\n"
                              
                              "CRITICAL SINGLE-PASS VALIDATION RULE:\n"
                              "Before finalizing the output array, you must run an internal mental simulation of the code replacement. If your proposed patch introduces broken syntax, incomplete placeholders, or structural erasures, discard it. You are the sole validation layer.\n\n"
                              
                              "CRITICAL RULES FOR THE PATCHES ARRAY (REPLACEMENT SAFETY & TOKEN ECONOMY):\n"
                              "1. Patches MUST be completely atomic. Never rewrite whole functions, routes, boilerplate setups, or files inside a single 'corrected_snippet'.\n"
                              "2. Each patch must target a maximum of 5 to 10 lines of code. If a file requires multiple separate changes (e.g., adding an import at the top, then modifying a variable assignment later), you MUST split them into separate, tiny, isolated entries in the patches array.\n"
                              "3. The 'original_snippet' MUST act as a precise, unambiguous anchor window. It must capture exactly 2 lines of unchanged code ABOVE the vulnerability, the target vulnerable code lines themselves, and exactly 2 lines of unchanged code BELOW the vulnerability.\n"
                              "4. The 'corrected_snippet' must contain those exact same upper and lower unchanged anchor lines wrapping around your newly corrected secure code in the middle. This ensures standard local string .replace() swaps the contents perfectly without leaving duplicate lines or breaking adjacent syntax.\n"
                              "5. Never write code placeholders like '// ...' or '// rest of code'. Everything within that 5-10 line targeted target window must be fully written out.\n"
                              "6. Never set 'corrected_snippet' to an empty string to delete code blocks. Always provide surrounding context characters to ensure precise matching.\n"
                              "7. Never use a single code statement or comment line as an anchor to inject completely new structural entities (like whole new middleware blocks, functions, or unrelated API routes). If a brand-new helper function or middleware must be added to a file, it MUST be its own isolated patch targeting the top imports area or an explicit file boundary.\n"
                              "8. If a security fix requires a heavy architectural rewrite that cannot be safely executed via this precise micro-window bounding, DO NOT generate a patch for it; only document it conceptually in the report suggestions."
                        ),
                        'response_mime_type':'application/json',
                        'response_schema':SentinalReport,
                  }
                  )
            elif Smode == "repair":
                  Prompt_push = (f"""
                              You are receiving raw source code text from a file. Your sole job is to act as a rigorous compiler and runtime debugger to find exactly what will cause this code to crash or fail to compile.

                              ======================================================================
                              TARGET SOURCE CODE:
                              ======================================================================
                              {codebase}
                              ======================================================================

                              EXECUTION ASSIGNMENT:
                              1. IDENTIFY COMPILATION & RUNTIME CRASHES:
                              - Scan the code top-to-bottom for syntax errors, missing markers, bracket/brace mismatches, and undefined variable references.
                              - Look closely for runtime type-mismatch bugs (such as passing a dictionary object instead of a string path into file operations).
                              - Log these execution-breaking bugs inside the 'vulnerabilities_found' array.

                              2. MENTAL TEST PASS:
                              - Before outputting a fix, simulate running the corrected code block.
                              - Ensure your patch fixes the compilation/runtime error *without* changing the surrounding architecture or introducing new bugs.

                              3. CONTEXT-ANCHOR PATCH MATCHING:
                              - For each bug, generate a microscopic patch inside the 'patches' array.
                              - The 'original_snippet' MUST contain exactly 2 lines of unchanged code directly ABOVE the error, the broken code lines exactly as they appear, and exactly 2 lines of unchanged code directly BELOW the error.
                              - The 'corrected_snippet' MUST preserve those exact upper and lower context lines with zero changes to whitespace or indentation, cleanly wrapping your fixed code inside the middle.
                              - Do not use placeholders like '// ...'. Write out the 5-10 line window completely.

                              Output the results in raw, valid JSON matching your schema format exactly.
                              """)
                  
                  print("Analyzing Folder structure... Please wait.")

                  response = clint.models.generate_content(
                  model='gemini-2.5-flash',
                  contents=Prompt_push,
                  config={
                        'system_instruction': (
                              "You are Sentinel, an automated multi-language compiler engineer and intensive runtime debugger. "
                              "Your sole goal is to perform a strict line-by-line validation of target source files to identify syntax errors, logical defects, and execution-breaking bugs.\n\n"
                              
                              "CRITICAL OUTPUT RULE FOR THE 'Suggestion' FIELD:\n"
                              "1. If code errors or compilation barriers exist, dedicate the 'Suggestion' string entirely to explaining the mechanical breakdown preventing clean execution.\n"
                              "2. If the code is completely bug-free and compile-safe, suggest 2-3 advanced architectural optimizations or memory performance expansions tailored to the project.\n\n"
                              
                              "CRITICAL SINGLE-PASS VALIDATION RULE:\n"
                              "Before finalizing your response schema, you must run an internal mental compilation simulation of your proposed patch. If your fix introduces broken syntax, unhandled exceptions, incomplete placeholders, or structural imbalances, discard it immediately. You are the sole validation layer.\n\n"
                              
                              "CRITICAL RULES FOR THE PATCHES ARRAY (REPLACEMENT SAFETY):\n"
                              "1. Patches MUST be completely atomic. Target only the specific line(s) causing the failure. Never rewrite whole functions, routes, boilerplate setups, or files inside a single 'corrected_snippet'.\n"
                              "2. Each patch must target a maximum of 5 to 10 lines of code.\n"
                              "3. The 'original_snippet' MUST act as a precise, unique, and unambiguous character-for-character anchor window. It must capture exactly 2 lines of unchanged code directly ABOVE the error, the broken statement lines exactly as they appear in the source, and exactly 2 lines of unchanged code directly BELOW the error.\n"
                              "4. The 'corrected_snippet' must contain those exact same upper and lower unchanged context anchor lines, cleanly wrapping your fixed code inside the middle. You must preserve the exact whitespace, indentation depth, and characters of the anchor lines so the local python string .replace() mapping succeeds perfectly.\n"
                              "5. Never write code placeholders like '// ...' or '# rest of code'. Everything within that target window must be fully written out."
                        ),
                        'response_mime_type':'application/json',
                        'response_schema':SentinalReport,
                  }
                  )

            raw_text = (response.text or "").strip()

            if raw_text.startswith("```"):
                  lines = raw_text.splitlines()
                  if lines[0].startswith("```"):
                        lines = lines[1:]
                  if lines[-1].startswith("```"):
                        lines = lines[:-1]
                  raw_text = "\n".join(lines).strip()

            report = json.loads(raw_text)

            print("\n================ SENTINEL ANALYSIS REPORT ================\n")
            print("\n" + "="*60)
            print(f" SENTINEL SCAN REPORT: {report.get('file_name', 'Unknown Target')}")
            print("="*60)
            print(f" Detected Languages : {report.get('language')}")
            print(f" Posture Risk Level : {report.get('risk_level')}")
            print(f" Complexity Score   : {report.get('complexity_score')}")
            print(f" Core Objective     : {report.get('summary')}")
            print("-"*60)
            
            print(f" Found Issues/Bugs ({len(report.get('vulnerabilities_found', []))}):")
            if report.get("vulnerabilities_found"):
                for idx, bug in enumerate(report["vulnerabilities_found"], 1):
                    print(f"   {idx}. {bug}")
            else:
                print("   [+] No execution-breaking defects identified.")
            print("-"*60)

            print(" Mechanics & Weaponization Vectors:")
            if report.get("Attacks"):
                for attack in report["Attacks"]:
                    print(f"   • {attack}")
            else:
                print("   [-] None.")
            print("-"*60)

            print(f" Strategic Recommendation:\n   {report.get('Suggestion')}")
            print("="*60 + "\n")
            print("\n==========================================================\n")

            temp = f"{Spath}\\sentinal.txt"
            with open(temp,"w", encoding="utf-8") as wds:
                  json.dump(report, wds, indent=2)

            if report.get("patches"):
                  print(f"Sentinal deteched {len(report['patches'])} areas required security updates")
                  user_input = input("Do you grant sentinel permission to insitate the fix of the problem : ")

                  if user_input == 'y':
                        Filepath = os.path.join(Spath, "Sentinal_report.txt")
                        print(f"Initiating Virtual Environment Workspace in: {Filepath}")
                        with open(Filepath, "w", encoding="utf-8") as stage_file:
                              stage_file.write("="*60 + "\n")
                              stage_file.write(f" SENTINEL AUTOMATED REMEDIATION REPORT: {report.get('file_name')}\n")
                              stage_file.write("="*60 + "\n\n")
                              stage_file.write(f"Detected Languages : {report.get('language')}\n")
                              stage_file.write(f"Posture Risk Level : {report.get('risk_level')}\n")
                              stage_file.write(f"Complexity Score   : {report.get('complexity_score')}\n")
                              stage_file.write(f"Core Summary       : {report.get('summary')}\n\n")
                              stage_file.write("-"*60 + "\n")
                              stage_file.write("IDENTIFIED LOGICAL FAULTS & SYSTEM THREATS:\n")
                              for bug in report.get("vulnerabilities_found", []):
                                    stage_file.write(f" - {bug}\n")
                              for attack in report.get("Attacks", []):
                                    stage_file.write(f"   * Exploit Profile: {attack}\n")
                              stage_file.write("-"*60 + "\n\n")
                              
                              stage_file.write("ENGINEERED REPAIR PATCH PAYLOADS:\n")
                              for problem in report["patches"]:
                                    stage_file.write(f"Target File Modification Window: {problem['target_file']}\n")
                                    stage_file.write(f"----Original Code Window----\n{problem['original_snippet']}\n---\n")
                                    stage_file.write(f"-----Proposed Corrected Code-----\n{problem['corrected_snippet']}\n")
                                    stage_file.write("="*40 + "\n\n")
                        print("Checking if the code aligns with your thinking.....")

                        commit_perm = input("Would you like to commit these changes and overwrite the original files? (y/n): ").strip().lower()

                        if commit_perm == 'y':
                              print("Launching the code in the current codebase")
                              file_buffers = {}

                              for patchwork in report["patches"]:
                                    targetfile = os.path.normpath(os.path.join(Spath, patchwork["target_file"]))
                                    project_root_norm = os.path.normpath(Spath)

                                    # SECURITY: Validate that the resolved target file is strictly within the project directory
                                    if not targetfile.startswith(project_root_norm + os.sep) and targetfile != project_root_norm:
                                          print(f"SECURITY ALERT: Path traversal attempt detected for '{patchwork['target_file']}'. Skipping patch to prevent arbitrary file overwrite.")
                                          continue
                                    if targetfile not in file_buffers:
                                          with open(targetfile, "r", encoding="utf-8") as rf:
                                                file_buffers[targetfile] = rf.read()
                                    current_content = file_buffers[targetfile]
                                    if patchwork["original_snippet"] in current_content:
                                          file_buffers[targetfile] = current_content.replace(
                                                patchwork["original_snippet"], 
                                                patchwork["corrected_snippet"]
                                          )
                              for targetfile, final_content in file_buffers.items():
                                    with open(targetfile, "w", encoding="utf-8") as wf:
                                          wf.write(final_content)
                                          print(f"Code patch succes at: {patchwork['target_file']}")
                                    logged_rel = os.path.relpath(targetfile, Spath)
                                    print(f"Code patch success written to disk at: {logged_rel}")
                         
                        else:
                              print("commit process aborted")
                              with open(Filepath, "a", encoding="utf-8") as reupdate:
                                    reupdate.write("\n CRITICAL WARNING: These patches have NOT been integrated into your main source code files. Your application remains exposed to the vulnerabilities outlined above, and manual application may result in build failures if context mappings conflict.\n")
                              print(f"The report and the suggest code replacements are saved in the codebase at : {Filepath}")   
                  else:
                        print("Overall Codebase Posture: SAFE. No code adjustments required.")


      except errors.APIError as api_err:
            print(f" Gemini API Error: {api_err}")
      except Exception as e:
            print(f"Unexcpected error : {e}")

if __name__ == "__main__":
      main()     
      # if os.path.exists(Filepath):
      #       os.remove(Filepath)
      #       print("Temperory files deleted succes")