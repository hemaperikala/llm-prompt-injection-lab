import base64
import codecs
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.bot_secure import output_leaks, output_leaks_v2, SECRET

samples = {
    "plain text": SECRET,
    "reversed": SECRET[::-1],
    "spaced letters": " ".join(SECRET),
    "base64": base64.b64encode(SECRET.encode()).decode(),
    "hex": SECRET.encode().hex(),
    "hex spaced": " ".join(f"{b:02x}" for b in SECRET.encode()),
    "rot13": codecs.encode(SECRET, "rot13"),
    "digits as words": "SECRET-one two three four",
    "caesar shift +3": "".join(chr(ord(c) + 3) for c in SECRET),
    "normal reply": "Your order #4521 shipped yesterday and arrives Friday.",
}

print(f"{'sample':18} {'filter v1':10} {'filter v2':10}")
for name, text in samples.items():
    print(f"{name:18} {str(output_leaks(text)):10} {str(output_leaks_v2(text)):10}")
print("\nTrue = leak caught. For 'normal reply', True would be a false positive.")