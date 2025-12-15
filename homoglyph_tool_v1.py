import os
import random
import threading
import webbrowser
import unicodedata
import idna 
import re # For URL detection
from flask import Flask, request, render_template_string, jsonify

# ==========================================
# CONFIGURATION
# ==========================================
# Data file loaded from the script's directory
DATA_FILE = "chars.txt" 
HOST = "127.0.0.1"
PORT = 8080
MAX_SINGLE_SPOOFS = 10 

app = Flask(__name__)

# ==========================================
# GLOBAL DATA
# ==========================================
homoglyph_map = {} # char -> list of homoglyphs
homoglyph_chars = set() # Set for quick homoglyph check

def load_data():
    """Parses the chars.txt file to build the homoglyph mapping."""
    if not os.path.exists(DATA_FILE):
        print(f"[!] Warning: '{DATA_FILE}' not found. Please create it with the homoglyph data.")
        return

    print(f"[*] Loading homoglyph data from {DATA_FILE}...")
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                chars_in_group = list(line)
                
                for char in chars_in_group:
                    if char not in homoglyph_map:
                        homoglyph_map[char] = []
                    homoglyph_map[char].extend(chars_in_group)
                    homoglyph_chars.add(char)
        
        # Deduplicate lists
        for k in homoglyph_map:
            unique_chars = sorted(list(set(homoglyph_map[k])), key=lambda c: ord(c))
            homoglyph_map[k] = unique_chars
            
        print(f"[*] Loaded {len(homoglyph_map)} homoglyph groups.")
    except Exception as e:
        print(f"[!] Error loading file: {e}")

# ==========================================
# PUNYCODE & HELPER FUNCTIONS
# ==========================================

def punycode_encode(unicode_text):
    """Converts a unicode string to its Punycode (IDN) representation."""
    # Split by dot to handle individual domain components
    parts = unicode_text.split('.')
    encoded_parts = []
    
    for part in parts:
        try:
            # Check if the part contains non-ASCII characters
            if any(ord(c) > 127 for c in part):
                # IDNA encoding (Punycode)
                encoded_parts.append(idna.encode(part).decode('ascii'))
            else:
                encoded_parts.append(part)
        except idna.IDNAError as e:
            return f"Punycode Error: {e}"
        except Exception as e:
            return f"Punycode Error: {e}"

    return ".".join(encoded_parts)

def get_script_name(char):
    """Extracts the Unicode script/block name."""
    try:
        name = unicodedata.name(char)
        if 'CYRILLIC' in name: return 'CYRILLIC'
        if 'GREEK' in name: return 'GREEK'
        if 'ARMENIAN' in name: return 'ARMENIAN'
        if 'FULLWIDTH' in name: return 'FULLWIDTH'
        if ord(char) < 128: return 'LATIN'
        return 'OTHER'
    except ValueError:
        return 'UNKNOWN'

# ==========================================
# ATTACK & DETECTION LOGIC
# ==========================================

def detect_attack(text):
    """Analyzes text for homoglyphs and generates Punycode if applicable."""
    results = []
    suspicious_count = 0
    contains_dot = '.' in text
    contains_non_ascii = False

    for char in text:
        codepoint = "U+{:04X}".format(ord(char))
        try:
            name = unicodedata.name(char)
        except ValueError:
            name = "UNKNOWN"
            
        is_suspicious = False
        is_ascii = ord(char) < 128
        
        if is_ascii:
            status = "safe"
            note = "Safe (ASCII)"
        else:
            contains_non_ascii = True
            if char in homoglyph_chars:
                is_suspicious = True
                status = "danger"
                note = f"Homoglyph ({get_script_name(char)})"
            else:
                status = "warning"
                note = f"Non-ASCII ({get_script_name(char)})"

        if is_suspicious:
            suspicious_count += 1

        results.append({
            "char": char,
            "hex": codepoint,
            "name": name,
            "status": status,
            "note": note
        })
        
    punycode_output = None
    if contains_dot and contains_non_ascii:
        # Only encode to punycode if it looks like a domain AND has non-ASCII chars
        punycode_output = punycode_encode(text)

    return results, suspicious_count, punycode_output

def generate_attack_variants(text):
    """Generates multiple spoofed texts with targeted strategies and Punycode."""
    variants = []
    target_scripts = ['CYRILLIC', 'GREEK', 'ARMENIAN', 'FULLWIDTH']
    
    # --- Strategy 1: Script-Uniform Spoofs ---
    for script_name in target_scripts:
        spoof_text = ""
        changes = 0
        
        for char in text:
            # Check for homoglyphs for letters AND special chars like '.'
            is_spoofable = char in homoglyph_map
            
            if is_spoofable:
                # Find homoglyphs of this character that belong to the target script
                script_alternatives = [
                    c for c in homoglyph_map[char] 
                    if c != char and get_script_name(c) == script_name
                ]
                
                if script_alternatives:
                    # Pick a random one from the chosen script
                    spoof_text += random.choice(script_alternatives)
                    changes += 1
                else:
                    spoof_text += char
            else:
                spoof_text += char

        if changes > 0:
            punycode = punycode_encode(spoof_text)
            
            variants.append({
                "type": f"Uniform Spoof ({script_name})",
                "spoof": spoof_text,
                "changes": changes,
                "note": "Most characters replaced by the same script.",
                "punycode": punycode
            })

    # --- Strategy 2: Single-Character Spoof (Typo Attack) ---
    single_spoof_count = 0
    generated_spoofs = set()

    # Iterate through only Latin letters for targeted single-char spoofs
    for i, original_char in enumerate(text):
        if get_script_name(original_char) == 'LATIN' and original_char in homoglyph_map:
            
            # Get all non-Latin homoglyphs for the original character
            alternatives = [
                c for c in homoglyph_map[original_char] 
                if c != original_char and ord(c) > 128
            ]
            
            for spoof_char in sorted(set(alternatives), key=lambda c: ord(c))[:2]:
                
                spoof_text = text[:i] + spoof_char + text[i+1:]
                
                if spoof_text not in generated_spoofs:
                    generated_spoofs.add(spoof_text)
                    punycode = punycode_encode(spoof_text)

                    variants.append({
                        "type": f"Single Char Spoof ('{original_char}' -> '{spoof_char}')",
                        "spoof": spoof_text,
                        "changes": 1,
                        "note": f"Only one character was replaced with a {get_script_name(spoof_char)} homoglyph.",
                        "punycode": punycode
                    })
                    single_spoof_count += 1

                if single_spoof_count >= MAX_SINGLE_SPOOFS:
                    break
        
        if single_spoof_count >= MAX_SINGLE_SPOOFS:
            break

    return variants

# ==========================================
# WEB INTERFACE (HTML/JS)
# ==========================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Homoglyph Toolkit</title>
    <style>
        body { font-family: sans-serif; background: #f0f2f5; margin: 0; padding: 20px; }
        .container { max-width: 900px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { text-align: center; color: #333; }
        .tabs { display: flex; border-bottom: 2px solid #ddd; margin-bottom: 20px; }
        .tab { flex: 1; padding: 15px; text-align: center; cursor: pointer; background: #fafafa; font-weight: bold; }
        .tab.active { background: white; border-bottom: 3px solid #007bff; color: #007bff; }
        .content { display: none; }
        .content.active { display: block; }
        
        textarea { width: 100%; height: 80px; padding: 10px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px; margin-bottom: 10px; resize: vertical; }
        button { background: #007bff; color: white; border: none; padding: 10px 20px; cursor: pointer; border-radius: 4px; font-size: 16px; width: 100%; }
        button:hover { background: #0056b3; }
        
        /* NEW: Punycode Styling */
        .generated-box { 
            background: #e9ecef; 
            padding: 15px; 
            border-radius: 4px; 
            font-family: monospace; 
            font-size: 1.2em; 
            word-break: break-all; 
            margin-top: 10px;
            border-left: 5px solid #007bff;
        }
        .punycode-box {
            background: #f9f9f9;
            padding: 8px 15px;
            margin-top: 5px;
            border: 1px dashed #ccc;
            font-size: 0.9em;
            color: #6c757d;
        }

        .result-group { margin-bottom: 20px; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
        .result-group h4 { margin-top: 0; margin-bottom: 5px; color: #007bff; }

        /* Detection Results Table */
        table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f8f9fa; }
        .char-cell { font-size: 1.5em; text-align: center; font-family: monospace; }
        
        .safe { background-color: #d4edda; color: #155724; }
        .warning { background-color: #fff3cd; color: #856404; }
        .danger { background-color: #f8d7da; color: #721c24; font-weight: bold; }
    </style>
</head>
<body>

<div class="container">
    <h1>Homoglyph Attack Toolkit</h1>
    <p style="text-align: center; color: #666;">IDN (Punycode) generation and detection included.</p>
    
    <div class="tabs">
        <div class="tab active" onclick="setTab('detect', this)">🛡️ Detect Attack</div>
        <div class="tab" onclick="setTab('generate', this)">⚔️ Create Attack (Encoder)</div>
    </div>

    <div id="detect" class="content active">
        <h3>Input Text for Analysis</h3>
        <p>Paste text to identify if characters are being spoofed.</p>
        <textarea id="detect-input" placeholder="Enter suspicious text here... (e.g. apple.com using Cyrillic 'а')"></textarea>
        <button onclick="runDetection()">Analyze Text</button>
        <div id="detect-output"></div>
    </div>

    <div id="generate" class="content">
        <h3>Input Text for Encoding</h3>
        <p>Enter normal text (e.g. google.com) to generate multiple spoofed versions.</p>
        <textarea id="gen-input" placeholder="Enter normal text (e.g. google.com)..."></textarea>
        <button onclick="runGeneration()">Generate Spoofs</button>
        <div id="gen-output"></div>
    </div>
</div>

<script>
    function setTab(name, element) {
        document.querySelectorAll('.content').forEach(d => d.classList.remove('active'));
        document.querySelectorAll('.tab').forEach(d => d.classList.remove('active'));
        document.getElementById(name).classList.add('active');
        element.classList.add('active');
    }

    // --- Detection Logic ---
    async function runDetection() {
        const text = document.getElementById('detect-input').value;
        const outputDiv = document.getElementById('detect-output');
        outputDiv.innerHTML = 'Analyzing...';

        const res = await fetch('/api/detect', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({text})
        });
        const data = await res.json();
        
        let html = '';

        // Add Punycode if available
        if (data.punycode_output) {
            html += `<div class="punycode-box" style="margin-bottom: 15px; border-left: 5px solid #ffc107;">
                <strong>URL/Domain Detected!</strong><br>
                This string converts to Punycode: 
                <span style="font-weight: bold; color: #dc3545; word-break: break-all;">${data.punycode_output}</span>
            </div>`;
        }

        if(data.count > 0) html += `<h3 style="color:red">⚠️ Found ${data.count} potentially deceptive character(s)!</h3>`;
        else html += `<h3 style="color:green">✅ No obvious homoglyphs detected.</h3>`;


        html += '<table><thead><tr><th>Char</th><th>Hex</th><th>Unicode Name</th><th>Status/Note</th></tr></thead><tbody>';
        data.results.forEach(r => {
            html += `<tr class="${r.status}">
                <td class="char-cell">${r.char}</td>
                <td>${r.hex}</td>
                <td>${r.name}</td>
                <td>${r.note}</td>
            </tr>`;
        });
        html += '</tbody></table>';
        
        outputDiv.innerHTML = html;
    }

    // --- Generation Logic ---
    async function runGeneration() {
        const text = document.getElementById('gen-input').value;
        const outputDiv = document.getElementById('gen-output');
        outputDiv.innerHTML = 'Generating...';
        
        const res = await fetch('/api/generate', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({text})
        });
        const data = await res.json();
        
        let html = `<h3>Generated Spoofs (${data.results.length} variants):</h3>`;
        
        data.results.forEach(r => {
            html += `
                <div class="result-group">
                    <h4>${r.type}</h4>
                    <p style="font-size: 0.9em; margin-bottom: 5px;">${r.note} (${r.changes} changes)</p>
                    <div class="generated-box">
                        <strong>Unicode Spoof:</strong> ${r.spoof}
                    </div>
                    <div class="punycode-box">
                        <strong>Punycode (IDN):</strong> ${r.punycode}
                    </div>
                </div>
            `;
        });
        
        outputDiv.innerHTML = html;
    }
</script>

</body>
</html>
"""

# ==========================================
# FLASK ROUTES
# ==========================================

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/detect', methods=['POST'])
def api_detect():
    data = request.json
    text = data.get('text', '')
    results, count, punycode = detect_attack(text) # New return value
    return jsonify({'results': results, 'count': count, 'punycode_output': punycode})

@app.route('/api/generate', methods=['POST'])
def api_generate():
    data = request.json
    text = data.get('text', '')
    variants = generate_attack_variants(text)
    return jsonify({'results': variants})

def open_browser():
    """Opens the browser on server start."""
    webbrowser.open_new(f"http://{HOST}:{PORT}/")

# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == '__main__':
    # Load the dictionary from the file on disk
    load_data()
    
    # Start browser in separate thread
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or True:
        threading.Timer(1, open_browser).start()
    
    # Run Server
    print(f"[*] Starting server at http://{HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=False)